/**
 * Tauri 2 Plugin HTTP Client for JavaScript / TypeScript
 * Compatible with @tauri-apps/plugin-http
 */

export class HttpResponse {
  constructor(payload) {
    this.status = payload.status;
    this.statusText = payload.statusText;
    this.ok = payload.ok;
    this.headers = new Headers(payload.headers || {});
    this.url = payload.url;
    this._data = payload.data || "";
  }

  async text() {
    return this._data;
  }

  async json() {
    return JSON.parse(this._data);
  }
}

export async function fetch(url, options = {}) {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) throw new Error("Tauri IPC bridge not found");

  const payload = await invoke('plugin:http|fetch', {
    url: url,
    options: options
  });

  return new HttpResponse(payload);
}

export default {
  fetch
};
