rule Suspicious_Python_Setup_Email {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup scripts with potentially malicious author emails"
        confidence = "70"
        severity = "60"
        
    strings:
        $setup = "setup("
        $author_email = "author_email"
        $vulnium = "vulnium.com"
        
    condition:
        all of them
}