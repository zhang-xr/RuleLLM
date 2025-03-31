rule Malicious_Python_Browser_Extension_Dropper {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based malware that drops malicious browser extensions and modifies browser shortcuts"
        confidence = 90
        severity = 85
        
    strings:
        $win32_check = "if sys.platform == 'win32'"
        $pypiwin32_install = "main(['install', 'pypiwin32'])"
        $extension_path = "appDataPath + '\\\\Extension'"
        $shortcut_mod = "shortcut.Arguments = '--load-extension='"
        $browser_targets = /chrome\.exe|msedge\.exe|launcher\.exe|brave\.exe/
        $manifest_json = /"permissions":\s*\["clipboardWrite",\s*"clipboardRead"\]/
        $obfuscated_js = /var _0x[0-9a-f]{4,6}=_0x[0-9a-f]{4,6};/
        
    condition:
        all of ($win32_check, $pypiwin32_install) and 
        any of ($extension_path, $shortcut_mod) and
        any of ($browser_targets, $manifest_json, $obfuscated_js)
}