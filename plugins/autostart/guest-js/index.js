/**
 * Tauri 2 Plugin Autostart for JavaScript / TypeScript
 * Compatible with @tauri-apps/plugin-autostart
 */
export async function isEnabled() {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) throw new Error("Tauri IPC bridge not found");
  return invoke('plugin:autostart|is_enabled');
}

export async function enable() {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) throw new Error("Tauri IPC bridge not found");
  return invoke('plugin:autostart|enable');
}

export async function disable() {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) throw new Error("Tauri IPC bridge not found");
  return invoke('plugin:autostart|disable');
}

export default {
  isEnabled,
  enable,
  disable
};
