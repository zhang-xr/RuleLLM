rule Discord_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using Discord webhooks for data exfiltration"
        confidence = 90
        severity = 80

    strings:
        $discord_webhook = "SyncWebhook.from_url"
        $webhook_send = "webhook.send"
        $socket_gethostname = "socket.gethostname"
        $socket_gethostbyname = "socket.gethostbyname"
        $platform_info = "platform." nocase

    condition:
        all of them and filesize < 10KB
}