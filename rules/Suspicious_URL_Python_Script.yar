rule Suspicious_URL_Python_Script {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URLs in Python scripts"
        confidence = 75
        severity = 65

    strings:
        $url_pattern = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/

    condition:
        $url_pattern
}