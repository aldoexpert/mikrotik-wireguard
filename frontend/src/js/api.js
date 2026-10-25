import config from '../config.js';
import store from './store.js';

// ApiError carries the server's message plus the original HTTP status.
export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function buildUrl(path, query) {
  const base = config.apiBaseUrl
    ? config.apiBaseUrl.replace(/\/?$/, '/')
    : window.location.origin + '/';
  const url = new URL(path.replace(/^\//, ''), base);
  if (query) {
    Object.entries(query).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    });
  }
  return url.toString();
}

// request calls module/controller/method (see backend/internal/core/router.go)
// and unwraps the standard {status, code, message, data, datas} envelope.
async function request(path, { method = 'GET', body, query } = {}) {
  const headers = {};
  const token = store.getters.token.value;
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let res;
  try {
    res = await fetch(buildUrl(path, query), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new ApiError('Could not connect to the server', 0);
  }

  if (res.status === 401) {
    store.dispatch('clearSession');
    if (!window.location.pathname.startsWith('/login')) {
      window.location.href = '/login/';
    }
  }

  const contentType = res.headers.get('Content-Type') || '';
  if (!contentType.includes('application/json')) {
    if (!res.ok) throw new ApiError(`HTTP ${res.status}`, res.status);
    return { response: res };
  }

  const payload = await res.json();
  if (!payload.status) {
    throw new ApiError(payload.message || 'Terjadi kesalahan', res.status);
  }
  return payload;
}

const api = {
  get: (path, query) => request(path, { method: 'GET', query }),
  post: (path, body) => request(path, { method: 'POST', body }),

  // downloadUrl builds an authenticated-less URL for endpoints meant to be
  // opened directly by the browser (file download). The backend's download
  // endpoint requires auth, so we fetch as a blob and trigger a save instead.
  async download(path, filename) {
    const token = store.getters.token.value;
    const res = await fetch(buildUrl(path), {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new ApiError(`HTTP ${res.status}`, res.status);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

export default api;
