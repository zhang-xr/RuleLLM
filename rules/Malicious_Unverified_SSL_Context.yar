rule Malicious_Unverified_SSL_Context {
    meta:
        author = "RuleLLM"
        description = "Detects the use of unverified SSL context to bypass certificate validation"
        confidence = 85
        severity = 75

    strings:
        $ssl_context = "ssl._create_unverified_context()"
        $urlopen = "urllib.request.urlopen"

    condition:
        all of them
}