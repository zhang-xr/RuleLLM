rule SSL_Context_Bypass {
    meta:
        author = "RuleLLM"
        description = "Detects the creation of an unverified SSL context to bypass certificate verification"
        confidence = 90
        severity = 70
    strings:
        $ssl_context = "ssl._create_unverified_context"
    condition:
        $ssl_context
}