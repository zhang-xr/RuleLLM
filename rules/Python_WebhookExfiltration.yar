rule Python_WebhookExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to exfiltrate data to a webhook URL"
        confidence = 80
        severity = 70

    strings:
        $webhook_url = /https?:\/\/[^\s]+webhook\.site[^\s]+/
        $curl_post = /curl.*-X\s+POST/
        $os_system = "os.system"

    condition:
        all of them
}