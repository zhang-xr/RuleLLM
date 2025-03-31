rule Python_Suspicious_Domain_0v0 {
    meta:
        author = "RuleLLM"
        description = "Detects usage of suspicious domain 0v0.in"
        confidence = 95
        severity = 85
    strings:
        $domain = "0v0.in"
        $https = "https://"
    condition:
        $https and $domain
}