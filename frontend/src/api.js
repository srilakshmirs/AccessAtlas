const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

/**
 * Helper to perform HTTP GET requests with unified error handling.
 */
async function apiGet(endpoint, params = {}) {
  const url = new URL(`${API_BASE}${endpoint}`);
  Object.entries(params).forEach(([key, val]) => {
    if (val !== undefined && val !== null && val !== '') {
      url.searchParams.append(key, val);
    }
  });

  try {
    const res = await fetch(url.toString(), {
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      let errMsg = `Request failed with status ${res.status}`;
      try {
        const errorData = await res.json();
        if (errorData.detail) {
          errMsg = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
        }
      } catch {
        // Fallback to text or default message
      }
      throw new Error(errMsg);
    }

    return await res.json();
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error(`Unable to connect to AccessAtlas API at ${API_BASE}. Please ensure the backend server is running.`);
    }
    throw err;
  }
}

export async function fetchHealth() {
  return apiGet('/health');
}

export async function fetchIdentities({ page = 1, size = 50, kind, tier, max_tier } = {}) {
  return apiGet('/identities', { page, size, kind, tier, max_tier });
}

export async function fetchIdentity(id) {
  return apiGet(`/identities/${encodeURIComponent(id)}`);
}

export async function fetchFindings({ page = 1, size = 50, rule, platform, severity, identity_id } = {}) {
  return apiGet('/findings', { page, size, rule, platform, severity, identity_id });
}

export async function fetchFinding(id) {
  return apiGet(`/findings/${encodeURIComponent(id)}`);
}

export async function fetchEvaluation(split = 'train') {
  return apiGet('/evaluation', { split });
}
