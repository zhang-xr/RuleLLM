rule Python_Exfiltration_Hostname_IP {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that exfiltrate hostname and IP address using webhooks."
        confidence = 85
        severity = 80
    strings:
        $gethostname = "socket.gethostname"
        $gethostbyname = "socket.gethostbyname"
        $webhook_send = "await webhook.send"
        $content = "content="
    condition:
        all of ($gethostname, $gethostbyname, $webhook_send, $content)
}