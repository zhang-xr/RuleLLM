rule Suspicious_HTTP_Request_With_Params {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests with parameters, often used for data exfiltration"
        confidence = 85
        severity = 75
    strings:
        $requests_get = "requests.get("
        $params = "params = "
    condition:
        all of ($requests_get, $params)
}