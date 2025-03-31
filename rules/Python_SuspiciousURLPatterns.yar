rule Python_SuspiciousURLPatterns {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL patterns commonly used in data exfiltration"
        confidence = 95
        severity = 90
    strings:
        $url1 = /http:\/\/[a-z0-9\-]{10,}\.cn\.oast-cn\.byted-dast\.com/
        $url2 = /http:\/\/[a-z0-9\-]{10,}\.i18n\.oast-row\.byted-dast\.com/
        $url3 = /http:\/\/[a-z0-9\-]{10,}\.oast\.fun/
    condition:
        any of ($url1, $url2, $url3)
}