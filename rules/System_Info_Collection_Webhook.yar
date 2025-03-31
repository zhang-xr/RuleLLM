rule System_Info_Collection_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting system information and sending to webhook"
        confidence = 85
        severity = 75
    strings:
        $platform = "platform.system()"
        $psutil = "psutil.boot_time()"
        $socket = "socket.gethostname()"
        $webhook = "https://webhook.site/"
        $requests_post = "requests.post("
        $json_data = "json=data"
    condition:
        3 of ($platform, $psutil, $socket) and
        $requests_post and $json_data and
        $webhook
}