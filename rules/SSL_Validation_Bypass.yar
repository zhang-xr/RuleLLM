rule SSL_Validation_Bypass {
    meta:
        author = "RuleLLM"
        description = "Detects SSL certificate validation bypass in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $ssl_unverified = "ssl._create_unverified_context"
        $urlopen_with_context = "urllib.request.urlopen"
    condition:
        $ssl_unverified and $urlopen_with_context
}