rule Suspicious_HTTP_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URLs used in HTTP requests, often associated with C2 servers"
        confidence = 85
        severity = 75

    strings:
        $http_request = "requests.get"
        $suspicious_url = /http:\/\/[a-zA-Z0-9]{8,}\.(requestrepo|interactsh|pipedream|burpcollaborator)\.(com|net)/

    condition:
        $http_request and $suspicious_url
}