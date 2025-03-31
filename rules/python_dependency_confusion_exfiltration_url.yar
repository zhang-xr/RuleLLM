rule python_dependency_confusion_exfiltration_url {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded exfiltration URLs in Python setup.py files"
        confidence = 95
        severity = 85

    strings:
        $exfiltration_url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9\-\.\/]+/
        $requests_get = "requests.get("

    condition:
        all of ($exfiltration_url, $requests_get)
}