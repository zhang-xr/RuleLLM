rule Python_Base64_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoding of data for exfiltration in Python scripts"
        confidence = 95
        severity = 85
    strings:
        $base64_encode = "base64.b64encode"
        $http_request = "requests.get"
        $decode_call = ".decode()"
        $url_param = "?data="
    condition:
        all of ($base64_encode, $http_request) and
        any of ($decode_call, $url_param)
}