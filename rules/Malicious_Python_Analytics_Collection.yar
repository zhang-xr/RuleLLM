rule Malicious_Python_Analytics_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system information and exfiltrates it to a remote server"
        confidence = 90
        severity = 80
    strings:
        $system_info = "platform.system()"
        $uptime = "psutil.boot_time()"
        $hostname = "socket.gethostname()"
        $webhook_url = /https?:\/\/[^\s]+\/analytics/
        $requests_post = "requests.post"
        $json_data = "json=data"
    condition:
        all of ($system_info, $uptime, $hostname) and 
        any of ($webhook_url, $requests_post) and 
        $json_data
}