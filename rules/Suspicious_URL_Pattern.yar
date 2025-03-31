rule Suspicious_URL_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URLs with randomly generated subdomains"
        confidence = 90
        severity = 80

    strings:
        $url_pattern = /https?:\/\/[a-z0-9]{16,}\.[a-z]{2,}\.oastify\.com/ nocase

    condition:
        $url_pattern
}