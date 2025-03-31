rule Suspicious_HTTP_Exfil_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious HTTP exfiltration URLs with random-looking subdomains"
        confidence = 85
        severity = 75

    strings:
        $url_pattern = /https?:\/\/[a-z0-9]{16,}\.oastify\.com/ ascii wide

    condition:
        $url_pattern and
        filesize < 10KB
}