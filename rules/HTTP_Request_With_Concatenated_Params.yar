rule HTTP_Request_With_Concatenated_Params {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests with concatenated parameters, often used in exfiltration"
        confidence = 90
        severity = 85

    strings:
        $http_request = "requests.get("
        $concat_pattern = /"[^"]+"\s*\+\s*"[^"]+"/

    condition:
        $http_request and $concat_pattern
}