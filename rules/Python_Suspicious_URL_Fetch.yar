rule Python_Suspicious_URL_Fetch {
    meta:
        author = "RuleLLM"
        description = "Detects the use of urllib.request.urlopen to fetch content from a suspicious domain."
        confidence = 80
        severity = 85

    strings:
        $urlopen = "urllib.request.urlopen("
        $suspicious_url = /https?:\/\/[^\s\/]+\.[^\s\/]+\/[^\s\)]+/

    condition:
        $urlopen and $suspicious_url
}