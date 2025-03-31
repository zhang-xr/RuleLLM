rule Suspicious_Base64_Exec_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious base64 execution patterns commonly used in Python malware"
        confidence = "85"
        severity = "80"
    
    strings:
        $base64_import = "__import__('base64').b64decode"
        $exec_function = "exec("
        $large_base64 = /[a-zA-Z0-9+\/]{100,}={0,2}/
    
    condition:
        all of them
}