local ffi = require("ffi")

pcall(ffi.cdef, [[
int _NSGetExecutablePath(char* buf, uint32_t* bufsize);
long readlink(const char *path, char *buf, size_t bufsiz);
unsigned long GetModuleFileNameA(void* hModule, char* lpFilename, unsigned long nSize);
int mkdir(const char *pathname, unsigned int mode);
int _mkdir(const char *pathname);

typedef void* HKEY;
typedef unsigned long DWORD;
typedef const char* LPCSTR;
typedef unsigned char BYTE;

long RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY *phkResult);
long RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, DWORD *lpReserved, DWORD *lpType, BYTE *lpData, DWORD *lpcbData);
long RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
long RegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
long RegCloseKey(HKEY hKey);
]])

local function safe_mkdir_p(target_path)
    if not target_path or target_path == "" or target_path == "." or target_path == "/" then
        return true
    end
    local normalized = target_path:gsub("\\", "/")
    local prefix = ""
    if normalized:match("^/") then
        prefix = "/"
        normalized = normalized:sub(2)
    elseif normalized:match("^[A-Za-z]:/") then
        prefix = normalized:sub(1, 3)
        normalized = normalized:sub(4)
    end

    local current = prefix
    for part in normalized:gmatch("[^/]+") do
        if part ~= "" and part ~= "." then
            current = (current == "" or current:match("/$")) and (current .. part) or (current .. "/" .. part)
            if ffi.os == "Windows" then
                pcall(function() ffi.C._mkdir(current) end)
            else
                pcall(function() ffi.C.mkdir(current, 493) end)
            end
        end
    end
    return true
end

local function sanitize_identifier(id)
    if type(id) ~= "string" or id == "" then
        return "com.tauri.lua"
    end
    -- Allow only alphanumeric, '.', '-', and '_'
    local cleaned = id:gsub("[^%w%-_%.]", "_")
    if cleaned == "" or cleaned:find("%.%.") then
        cleaned = "com.tauri.lua"
    end
    return cleaned
end

local function get_current_executable()
    local os_name = ffi.os
    if os_name == "OSX" then
        local buf = ffi.new("char[1024]")
        local size = ffi.new("uint32_t[1]", 1024)
        if ffi.C._NSGetExecutablePath(buf, size) == 0 then
            return ffi.string(buf)
        end
    elseif os_name == "Linux" then
        local buf = ffi.new("char[1024]")
        local len = ffi.C.readlink("/proc/self/exe", buf, 1024)
        if len > 0 then
            return ffi.string(buf, len)
        end
    elseif os_name == "Windows" then
        local buf = ffi.new("char[1024]")
        local len = ffi.C.GetModuleFileNameA(nil, buf, 1024)
        if len > 0 then
            return ffi.string(buf, len)
        end
    end
    return arg and arg[0] or ""
end

-- If running inside a macOS .app bundle, return the .app directory for cleaner launch
local function get_launch_target()
    local exe = get_current_executable()
    local app_bundle = exe:match("^(.*%.app)/Contents/MacOS/.*$")
    if app_bundle then
        return app_bundle, true -- is_app_bundle
    end
    return exe, false
end

local function escape_xml(s)
    local map = {
        ["&"] = "&amp;",
        ["<"] = "&lt;",
        [">"] = "&gt;",
        ['"'] = "&quot;",
        ["'"] = "&apos;"
    }
    return (s:gsub('[&<>"\']', map))
end

-- Win32 Registry Helper
local function get_advapi()
    if ffi.os ~= "Windows" then return nil end
    local ok, lib = pcall(ffi.load, "advapi32")
    return ok and lib or nil
end

-- ============================================================================
-- Autostart Plugin
-- ============================================================================
local AutostartPlugin = {}
AutostartPlugin.__index = AutostartPlugin

function AutostartPlugin.init(options)
    options = options or {}
    local plugin_inst = setmetatable({}, AutostartPlugin)
    plugin_inst.name = "autostart"
    plugin_inst.mac_launcher = options.mac_launcher or "LaunchAgent" -- LaunchAgent or AppleScript
    plugin_inst.app = nil

    local function get_app_meta()
        local app = plugin_inst.app
        local id = "com.tauri.lua"
        local name = "tauri-app"
        if app and app.config then
            id = app.config.identifier or (app.config.package and app.config.package.name) or id
            name = (app.config.package and app.config.package.name) or app.config.productName or name
        end
        return sanitize_identifier(id), name
    end

    local function is_enabled()
        local os_name = ffi.os
        local id, name = get_app_meta()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."

        if os_name == "OSX" then
            local plist_path = home .. "/Library/LaunchAgents/" .. id .. ".plist"
            local f = io.open(plist_path, "r")
            if f then
                f:close()
                return true
            end
            return false
        elseif os_name == "Linux" then
            local desktop_path = home .. "/.config/autostart/" .. id .. ".desktop"
            local f = io.open(desktop_path, "r")
            if f then
                f:close()
                return true
            end
            return false
        elseif os_name == "Windows" then
            local advapi = get_advapi()
            if advapi then
                local hkResult = ffi.new("HKEY[1]")
                if advapi.RegOpenKeyExA(ffi.cast("HKEY", 0x80000001), "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, 0x20019, hkResult) == 0 then
                    local hKey = hkResult[0]
                    local qRc = advapi.RegQueryValueExA(hKey, id, nil, nil, nil, nil)
                    advapi.RegCloseKey(hKey)
                    return qRc == 0
                end
            end
            return false
        end
        return false
    end

    local function enable()
        local os_name = ffi.os
        local id, name = get_app_meta()
        local target, is_bundle = get_launch_target()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."

        if os_name == "OSX" then
            local launch_agents_dir = home .. "/Library/LaunchAgents"
            safe_mkdir_p(launch_agents_dir)
            local plist_path = launch_agents_dir .. "/" .. id .. ".plist"

            local exec_args = ""
            if is_bundle then
                exec_args = string.format("        <string>/usr/bin/open</string>\n        <string>-a</string>\n        <string>%s</string>", escape_xml(target))
            else
                exec_args = string.format("        <string>%s</string>", escape_xml(target))
            end

            local plist_content = string.format([[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
%s
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>]], escape_xml(id), exec_args)

            local f = io.open(plist_path, "w")
            if not f then
                error(string.format("Failed to write LaunchAgent plist at %s", plist_path))
            end
            f:write(plist_content)
            f:close()
            return true

        elseif os_name == "Linux" then
            local autostart_dir = home .. "/.config/autostart"
            safe_mkdir_p(autostart_dir)
            local desktop_path = autostart_dir .. "/" .. id .. ".desktop"

            local desktop_content = string.format([[
[Desktop Entry]
Type=Application
Version=1.0
Name=%s
Exec=%s
Terminal=false
StartupNotify=false
]], name, target)

            local f = io.open(desktop_path, "w")
            if not f then
                error(string.format("Failed to write XDG autostart file at %s", desktop_path))
            end
            f:write(desktop_content)
            f:close()
            return true

        elseif os_name == "Windows" then
            local advapi = get_advapi()
            if advapi then
                local hkResult = ffi.new("HKEY[1]")
                if advapi.RegOpenKeyExA(ffi.cast("HKEY", 0x80000001), "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, 0x0002, hkResult) == 0 then
                    local hKey = hkResult[0]
                    local formatted_target = string.format('"%s"', target)
                    local sRc = advapi.RegSetValueExA(hKey, id, 0, 1, formatted_target, #formatted_target + 1)
                    advapi.RegCloseKey(hKey)
                    return sRc == 0
                end
            end
            return false
        end

        return false
    end

    local function disable()
        local os_name = ffi.os
        local id = get_app_meta()
        local home = os.getenv("HOME") or os.getenv("USERPROFILE") or "."

        if os_name == "OSX" then
            local plist_path = home .. "/Library/LaunchAgents/" .. id .. ".plist"
            os.remove(plist_path)
            return true
        elseif os_name == "Linux" then
            local desktop_path = home .. "/.config/autostart/" .. id .. ".desktop"
            os.remove(desktop_path)
            return true
        elseif os_name == "Windows" then
            local advapi = get_advapi()
            if advapi then
                local hkResult = ffi.new("HKEY[1]")
                if advapi.RegOpenKeyExA(ffi.cast("HKEY", 0x80000001), "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, 0x0002, hkResult) == 0 then
                    local hKey = hkResult[0]
                    local dRc = advapi.RegDeleteValueA(hKey, id)
                    advapi.RegCloseKey(hKey)
                    return dRc == 0 or dRc == 2
                end
            end
            return false
        end

        return false
    end

    return {
        name = "autostart",

        -- Direct Lua Backend API
        is_enabled = is_enabled,
        enable = enable,
        disable = disable,

        setup = function(app, self_plugin)
            plugin_inst.app = app

            app:register("plugin:autostart|is_enabled", function()
                return is_enabled()
            end)

            app:register("plugin:autostart|enable", function()
                return enable()
            end)

            app:register("plugin:autostart|disable", function()
                return disable()
            end)
        end,

        -- Injected Guest JavaScript API
        js = [[
            (function() {
                window.__TAURI_AUTOSTART__ = {
                    isEnabled: () => window.__TAURI__.invoke('plugin:autostart|is_enabled'),
                    enable: () => window.__TAURI__.invoke('plugin:autostart|enable'),
                    disable: () => window.__TAURI__.invoke('plugin:autostart|disable')
                };
                if (!window.__TAURI__) window.__TAURI__ = {};
                window.__TAURI__.autostart = window.__TAURI_AUTOSTART__;
            })();
        ]]
    }
end


pcall(function() package.loaded["tauri.plugin.autostart"] = AutostartPlugin end)
return AutostartPlugin
