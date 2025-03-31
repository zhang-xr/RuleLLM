rule Malicious_Setup_Deception {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of Python setup function as a decoy for malicious activity"
        confidence = 75
        severity = 70
    strings:
        $setup = "setup("
        $try_except = "try:"
        $except_pass = "except: pass"
    condition:
        $setup and 
        $try_except and 
        $except_pass
}