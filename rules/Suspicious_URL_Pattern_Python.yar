rule Suspicious_URL_Pattern_Python {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL patterns in Python code, often used for malicious downloads."
        confidence = 85
        severity = 75

    strings:
        $url_pattern = /https?:\/\/[^\s]+\?[a-zA-Z0-9+\/=]+/

    condition:
        $url_pattern and filesize < 10KB
}