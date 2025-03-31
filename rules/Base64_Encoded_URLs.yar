rule Base64_Encoded_URLs {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded URLs used for malicious communication"
        confidence = 95
        severity = 90

    strings:
        $b64_url1 = "aHR0cDovL2RuaXBxb3VlYm0tcHNsLmNuLm9hc3QtY24uYnl0ZWQtZGFzdC5jb20=" ascii
        $b64_url2 = "aHR0cDovL29xdmlnbmtwNTgtcHNsLmkxOG4ub2FzdC1yb3cuYnl0ZWQtZGFzdC5jb20=" ascii
        $b64_url3 = "aHR0cDovL3NiZndzdHNwdXV0aWFyY2p6cHRmM2MwY3ZiNnluZzZtdy5vYXN0LmZ1bg==" ascii
        $b64_decode = "b64.b64decode" ascii

    condition:
        any of ($b64_url1, $b64_url2, $b64_url3) and $b64_decode
}