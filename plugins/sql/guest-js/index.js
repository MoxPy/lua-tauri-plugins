/**
 * Tauri 2 Plugin SQL Client for JavaScript / TypeScript
 * Compatible with @tauri-apps/plugin-sql
 */
export class Database {
  constructor(path) {
    this.path = path;
  }

  static async load(path) {
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    if (!invoke) throw new Error("Tauri IPC bridge not found");
    const dbPath = await invoke('plugin:sql|load', { db: path });
    return new Database(dbPath);
  }

  async execute(query, values = []) {
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    return invoke('plugin:sql|execute', {
      db: this.path,
      query: query,
      values: values
    });
  }

  async select(query, values = []) {
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    return invoke('plugin:sql|select', {
      db: this.path,
      query: query,
      values: values
    });
  }

  async close() {
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    return invoke('plugin:sql|close', { db: this.path });
  }
}

export default Database;
