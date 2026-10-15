/**
 * Tauri 2 Plugin Window State for JavaScript / TypeScript
 * Compatible with @tauri-apps/plugin-window-state
 */
export async function saveWindowState(label = "main") {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) throw new Error("Tauri IPC bridge not found");

  return invoke('plugin:window-state|save', {
    label: label,
    state: {
      width: window.outerWidth || window.innerWidth,
      height: window.outerHeight || window.innerHeight,
      screenX: window.screenX,
      screenY: window.screenY,
      maximized: false,
      fullscreen: !!document.fullscreenElement
    }
  });
}

export async function restoreWindowState(label = "main") {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) throw new Error("Tauri IPC bridge not found");

  return invoke('plugin:window-state|restore', { label: label });
}

export default {
  saveWindowState,
  restoreWindowState
};
