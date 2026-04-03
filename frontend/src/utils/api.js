const BASE = '/api';

async function fetchJson(url) {
  const res = await fetch(`${BASE}${url}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export const api = {
  getDashboard: () => fetchJson('/dashboard'),
  getUsers: () => fetchJson('/users'),
  getUserDetail: (id) => fetchJson(`/users/${id}`),
  getAlerts: (severity) => fetchJson(`/alerts${severity ? `?severity=${severity}` : ''}`),
  getActivity: (userId, anomalousOnly = false, limit = 50) => {
    const params = new URLSearchParams();
    if (userId) params.set('user_id', userId);
    if (anomalousOnly) params.set('anomalous_only', 'true');
    params.set('limit', limit);
    return fetchJson(`/activity?${params}`);
  },
  getAnalytics: () => fetchJson('/analytics'),
  simulate: (scenario) => fetch(`${BASE}/simulate/${scenario}`, { method: 'POST' }).then(r => r.json()),
  triggerAnalysis: () => fetch(`${BASE}/analyze`, { method: 'POST' }).then(r => r.json()),
};
