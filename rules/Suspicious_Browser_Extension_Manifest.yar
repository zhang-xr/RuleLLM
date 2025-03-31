rule Suspicious_Browser_Extension_Manifest {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious browser extension manifests with clipboard permissions"
        confidence = 95
        severity = 90
        
    strings:
        $manifest_json = /"permissions":\s*\["clipboardWrite",\s*"clipboardRead"\]/
        $background_script = /"background":\s*{\s*"scripts":\s*\[[^\]]*\]/
        $version = /"version":\s*"[0-9]+"/
        
    condition:
        all of them and
        #manifest_json in (0..500) and
        #background_script in (0..500)
}