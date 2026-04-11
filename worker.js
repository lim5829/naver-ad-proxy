/**
 * 네이버 검색광고 API 프록시 — Cloudflare Workers
 * 
 * 배포 방법:
 *   1. npm install -g wrangler
 *   2. wrangler login
 *   3. wrangler deploy
 * 
 * 또는 Cloudflare 대시보드에서 직접 붙여넣기:
 *   1. https://dash.cloudflare.com → Workers & Pages → Create
 *   2. "Hello World" 템플릿 선택 → 이 코드 전체 붙여넣기 → Deploy
 */

// ─── CORS 헤더 ───
// 프로덕션에서는 "*" 대신 본인 도메인으로 제한 권장
// 예: "https://your-app.pages.dev"
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Customer-Id, X-Api-Key, X-Secret-Key, X-Manager-Login-Id",
  "Access-Control-Max-Age": "86400",
};

const NAVER_API_BASE = "https://api.searchad.naver.com";

// ─── HMAC-SHA256 서명 생성 (Web Crypto API) ───
async function generateSignature(timestamp, method, uri, secretKey) {
  const message = `${timestamp}.${method}.${uri}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secretKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// ─── 네이버 API 호출 ───
async function callNaverApi({ method, path, customerId, apiKey, secretKey, managerLoginId, body }) {
  const timestamp = Date.now().toString();
  
  // 서명은 query string 제외한 path만 사용
  const pathOnly = path.split("?")[0];
  const signature = await generateSignature(timestamp, method, pathOnly, secretKey);

  const headers = {
    "Content-Type": "application/json; charset=UTF-8",
    "X-Timestamp": timestamp,
    "X-API-KEY": apiKey,
    "X-Customer": String(customerId),
    "X-Signature": signature,
  };
  if (managerLoginId) headers["X-Manager-Login-Id"] = managerLoginId;

  const response = await fetch(`${NAVER_API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json();
  return { status: response.status, data };
}

// ─── JSON 응답 헬퍼 ───
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
    },
  });
}

// ─── 인증 헤더 추출 ───
function extractAuth(request) {
  const customerId = request.headers.get("X-Customer-Id");
  const apiKey = request.headers.get("X-Api-Key");
  const secretKey = request.headers.get("X-Secret-Key");
  const managerLoginId = request.headers.get("X-Manager-Login-Id");

  if (!customerId || !apiKey || !secretKey) {
    return { error: "Missing credentials: X-Customer-Id, X-Api-Key, X-Secret-Key 헤더가 필요합니다." };
  }
  return { customerId, apiKey, secretKey, managerLoginId };
}

// ─── 메인 핸들러 ───
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // ─── 헬스 체크 ───
    if (path === "/health") {
      return jsonResponse({ status: "ok", timestamp: new Date().toISOString() });
    }

    // ─── /api/* 라우트는 인증 필요 ───
    if (!path.startsWith("/api/")) {
      return jsonResponse({ error: "Not found" }, 404);
    }

    const auth = extractAuth(request);
    if (auth.error) return jsonResponse(auth, 401);

    try {
      // ─── 연결 테스트 ───
      if (path === "/api/test-connection" && request.method === "POST") {
        const result = await callNaverApi({
          method: "GET",
          path: "/ncc/campaigns",
          ...auth,
        });
        if (result.status >= 400) {
          return jsonResponse({ error: "Naver API error", detail: result.data }, result.status);
        }
        return jsonResponse({
          success: true,
          message: "API 연결 성공",
          campaignCount: Array.isArray(result.data) ? result.data.length : 0,
        });
      }

      // ─── 캠페인 목록 ───
      if (path === "/api/campaigns" && request.method === "GET") {
        const result = await callNaverApi({ method: "GET", path: "/ncc/campaigns", ...auth });
        return jsonResponse(result.data, result.status);
      }

      // ─── 캠페인 상세 ───
      const campaignDetailMatch = path.match(/^\/api\/campaigns\/([^/]+)$/);
      if (campaignDetailMatch && request.method === "GET") {
        const result = await callNaverApi({
          method: "GET",
          path: `/ncc/campaigns/${campaignDetailMatch[1]}`,
          ...auth,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 캠페인 ON/OFF ───
      const statusMatch = path.match(/^\/api\/campaigns\/([^/]+)\/status$/);
      if (statusMatch && request.method === "PUT") {
        const body = await request.json();
        const result = await callNaverApi({
          method: "PUT",
          path: `/ncc/campaigns/${statusMatch[1]}?fields=userLock`,
          ...auth,
          body: { userLock: body.userLock },
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 광고그룹 목록 ───
      if (path === "/api/adgroups" && request.method === "GET") {
        const campaignId = url.searchParams.get("campaignId");
        const naverPath = campaignId
          ? `/ncc/adgroups?nccCampaignId=${campaignId}`
          : "/ncc/adgroups";
        const result = await callNaverApi({ method: "GET", path: naverPath, ...auth });
        return jsonResponse(result.data, result.status);
      }

      // ─── 광고그룹 입찰가 수정 ───
      const adgroupBidMatch = path.match(/^\/api\/adgroups\/([^/]+)\/bid$/);
      if (adgroupBidMatch && request.method === "PUT") {
        const adgroupId = adgroupBidMatch[1];
        const body = await request.json();
        const result = await callNaverApi({
          method: "PUT",
          path: `/ncc/adgroups/${adgroupId}?fields=bidAmt`,
          ...auth,
          body: { 
            nccAdgroupId: adgroupId,
            bidAmt: body.bidAmt 
          },
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 광고그룹 하루예산 수정 ───
      const adgroupBudgetMatch = path.match(/^\/api\/adgroups\/([^/]+)\/budget$/);
      if (adgroupBudgetMatch && request.method === "PUT") {
        const adgroupId = adgroupBudgetMatch[1];
        const body = await request.json();
        const result = await callNaverApi({
          method: "PUT",
          path: `/ncc/adgroups/${adgroupId}?fields=dailyBudget`,
          ...auth,
          body: { 
            nccAdgroupId: adgroupId,
            dailyBudget: body.dailyBudget 
          },
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 광고그룹 상세 조회 ───
      const adgroupDetailMatch = path.match(/^\/api\/adgroups\/([^/]+)$/);
      if (adgroupDetailMatch && request.method === "GET") {
        const result = await callNaverApi({
          method: "GET",
          path: `/ncc/adgroups/${adgroupDetailMatch[1]}`,
          ...auth,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 키워드 목록 ───
      if (path === "/api/keywords" && request.method === "GET") {
        const adgroupId = url.searchParams.get("adgroupId");
        if (!adgroupId) {
          return jsonResponse({ error: "adgroupId query parameter is required" }, 400);
        }
        const result = await callNaverApi({
          method: "GET",
          path: `/ncc/adkeywords?nccAdgroupId=${adgroupId}`,
          ...auth,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 통계 리포트 (POST body) ───
      if (path === "/api/stats" && request.method === "POST") {
        const body = await request.json();
        const result = await callNaverApi({
          method: "POST",
          path: "/stats",
          ...auth,
          body,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 통계 요약 (GET with query params) ───
      if (path === "/api/stats-summary" && request.method === "GET") {
        const ids = url.searchParams.get("ids");
        const datePreset = url.searchParams.get("datePreset") || "today";
        const fields = url.searchParams.get("fields") || '["clkCnt","impCnt","salesAmt","cpc","ctr"]';
        
        if (!ids) {
          return jsonResponse({ error: "ids parameter is required" }, 400);
        }

        const statsPath = `/stats?ids=${encodeURIComponent(ids)}&fields=${encodeURIComponent(fields)}&datePreset=${datePreset}`;
        const result = await callNaverApi({
          method: "GET",
          path: statsPath,
          ...auth,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 통계 요약 (날짜 범위) ───
      if (path === "/api/stats-range" && request.method === "GET") {
        const ids = url.searchParams.get("ids");
        const since = url.searchParams.get("since");
        const until = url.searchParams.get("until");
        const fields = url.searchParams.get("fields") || '["clkCnt","impCnt","salesAmt","cpc","ctr"]';
        
        if (!ids || !since || !until) {
          return jsonResponse({ error: "ids, since, until parameters are required" }, 400);
        }

        const timeRange = JSON.stringify({ since, until });
        const statsPath = `/stats?ids=${encodeURIComponent(ids)}&fields=${encodeURIComponent(fields)}&timeRange=${encodeURIComponent(timeRange)}`;
        const result = await callNaverApi({
          method: "GET",
          path: statsPath,
          ...auth,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 키워드 도구 (검색량/경쟁도 조회) ───
      if (path === "/api/keywordstool" && request.method === "GET") {
        const hintKeywords = url.searchParams.get("hintKeywords");
        const showDetail = url.searchParams.get("showDetail") || "1";
        if (!hintKeywords) {
          return jsonResponse({ error: "hintKeywords parameter is required" }, 400);
        }
        const result = await callNaverApi({
          method: "GET",
          path: `/keywordstool?hintKeywords=${encodeURIComponent(hintKeywords)}&showDetail=${showDetail}`,
          ...auth,
        });
        return jsonResponse(result.data, result.status);
      }

      // ─── 광고주 정보 ───
      if (path === "/api/customer" && request.method === "GET") {
        const result = await callNaverApi({ method: "GET", path: "/customers", ...auth });
        return jsonResponse(result.data, result.status);
      }

      return jsonResponse({ error: "Endpoint not found", path, method: request.method }, 404);
    } catch (error) {
      console.error("Worker error:", error);
      return jsonResponse({ error: "Internal error", message: error.message }, 500);
    }
  },
};
