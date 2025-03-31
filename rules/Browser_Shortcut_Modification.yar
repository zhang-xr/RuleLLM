rule Browser_Shortcut_Modification {
    meta:
        author = "RuleLLM"
        description = "Detects modification of browser shortcuts to load extensions"
        confidence = 85
        severity = 80
        
    strings:
        $shortcut_mod = /shortcut\.Arguments\s*=\s*'--load-extension=/
        $browser_targets = /chrome\.exe|msedge\.exe|launcher\.exe|brave\.exe/
        $shell_object = "Dispatch('WScript.Shell')"
        
    condition:
        all of them
}