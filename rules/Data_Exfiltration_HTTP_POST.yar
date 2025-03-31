rule Data_Exfiltration_HTTP_POST {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP POST requests with encoded data for exfiltration."
        confidence = 90
        severity = 85

    strings:
        $http_post = "requests.post" ascii
        $data_dict = /data\s*=\s*\{.*\}/ ascii
        $timeout = "timeout=" ascii

    condition:
        all of them
}