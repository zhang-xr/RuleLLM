rule Base64_Exfiltration_In_Python_Package {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoding of data followed by HTTP requests in Python packages"
        confidence = "85"
        severity = "75"

    strings:
        $base64_encode = "base64.b64encode"
        $requests_get = "requests.get"
        $http_url = /https?:\/\/[^\s"]+/ ascii wide

    condition:
        // Match Base64 encoding and HTTP requests
        all of ($base64_encode, $requests_get) and
        $http_url
}