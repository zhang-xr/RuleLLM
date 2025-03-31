rule Malicious_Base64_Exec {
    meta:
        author = "RuleLLM"
        description = "Detects execution of base64-encoded Python code using exec()"
        confidence = "95"
        severity = "90"
        
    strings:
        $exec_pattern = /exec\s*\(\s*__import__\s*\(\s*.builtins\s*.\)\.compile\s*\(/
        $base64_decode = "__import__('base64').b64decode"
        $exec_call = "__import__('builtins').exec"
        
    condition:
        all of them
}