rule Unverified_SSL_Context {
    meta:
        author = "RuleLLM"
        description = "Detects the creation of an unverified SSL context, often used in malware to bypass certificate validation."
        confidence = 95
        severity = 85

    strings:
        $ssl_context = "ssl._create_unverified_context()"

    condition:
        $ssl_context
}