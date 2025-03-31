rule Data_Exfiltration_HTTP_POST {
    meta:
        author = "RuleLLM"
        description = "Detects potential data exfiltration via HTTP POST requests with system information"
        confidence = 80
        severity = 70
    strings:
        $http_post = "requests.post("
        $system_info1 = "platform.system()"
        $system_info2 = "psutil.boot_time()"
        $system_info3 = "socket.gethostname()"
        $json_data = "json=data"
    condition:
        all of ($system_info*) and $http_post and $json_data
}