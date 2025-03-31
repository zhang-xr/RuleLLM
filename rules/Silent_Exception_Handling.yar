rule Silent_Exception_Handling {
    meta:
        author = "RuleLLM"
        description = "Detects silent exception handling in Python code, often used to hide malicious activities."
        confidence = 80
        severity = 70
    
    strings:
        $try_except = "try:"
        $pass = "pass"
    
    condition:
        $try_except and $pass
}