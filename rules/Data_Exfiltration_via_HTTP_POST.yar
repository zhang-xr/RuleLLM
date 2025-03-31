rule Data_Exfiltration_via_HTTP_POST {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information and sends it to an external URL"
        confidence = 95
        severity = 90
    strings:
        $platform = "platform.system()"
        $psutil = "psutil.boot_time()"
        $socket = "socket.gethostname()"
        $requests_post = "requests.post('https://"
    condition:
        all of them
}