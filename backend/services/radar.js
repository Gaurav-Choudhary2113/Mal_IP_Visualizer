const BASE_URL = "https://api.cloudflare.com/client/v4";
const CACHE = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export async function fetchRadar(apiPath, query = {}) {
  const url = new URL(BASE_URL + apiPath);
  for (const [k, v] of Object.entries(query)) {
    url.searchParams.set(k, v);
  }
  const urlStr = url.toString();

  const cached = CACHE.get(urlStr);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.data;
  }

  const response = await fetch(urlStr, {
    headers: {
      Authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`
    }
  });

  const data = await response.json();
  CACHE.set(urlStr, { ts: Date.now(), data });
  return data;
}
