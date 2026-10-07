const API_BASE_URL = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

/**
 * Standardized API helper that handles JSON and non-JSON responses gracefully
 */
export async function apiFetch(endpoint, options = {}) {
  const url = endpoint.startsWith('http') 
    ? endpoint 
    : `${API_BASE_URL}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  let res;
  try {
    res = await fetch(url, options);
  } catch (networkError) {
    throw new Error(`Unable to reach backend server at ${url}. Please check your connection or server status.`);
  }

  const contentType = res.headers.get('content-type') || '';
  let data;

  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    const text = await res.text();
    if (!res.ok) {
      if (res.status === 404) {
        throw new Error(
          'API endpoint not found (404). Ensure your backend server is deployed and VITE_API_URL or proxy is correctly configured.'
        );
      }
      throw new Error(`Server returned HTTP ${res.status}: ${text.slice(0, 120)}`);
    }
    return text;
  }

  if (!res.ok) {
    throw new Error(data?.error || `Request failed with HTTP status ${res.status}`);
  }

  return data;
}

export { API_BASE_URL };
