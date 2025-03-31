rule Base64_Remote_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoding followed by communication with a remote server."
        confidence = 90
        severity = 85

    strings:
        $base64_encode = "base64.b64encode("
        $http_request = "request(url='http://"

    condition:
        $base64_encode and $http_request
}