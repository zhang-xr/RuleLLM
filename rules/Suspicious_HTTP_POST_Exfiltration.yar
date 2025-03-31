rule Suspicious_HTTP_POST_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that sends encoded data via HTTP POST requests."
        confidence = 85
        severity = 75

    strings:
        $http_post = "requests.post" ascii
        $base64_encode = "base64.b64encode" ascii
        $data_dict = /data\s*=\s*\{.*\}/ ascii

    condition:
        all of them
}