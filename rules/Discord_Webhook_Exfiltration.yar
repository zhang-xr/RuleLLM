rule Discord_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that initializes a Discord webhook and exfiltrates system information"
        confidence = 90
        severity = 80
    strings:
        $webhook_init = "SyncWebhook.from_url"
        $socket_gethost = /socket\.gethost(name|byname)/
        $webhook_send = "webhook.send"
    condition:
        all of them and filesize < 10KB
}