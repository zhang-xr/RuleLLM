rule Python_Exfiltration_HardcodedURL {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts with hardcoded URLs used for data exfiltration"
        confidence = 90
        severity = 85
    strings:
        $url = "https://shakedko.com/?oe-extract-ids12"
        $requests_get = "requests.get"
        $base64_encode = "base64.b64encode"
    condition:
        all of them
}