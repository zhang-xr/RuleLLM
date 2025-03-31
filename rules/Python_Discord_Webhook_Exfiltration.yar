rule Python_Discord_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that exfiltrate data to Discord webhooks during installation"
        confidence = 90
        severity = 80

    strings:
        $discord_webhook = "SyncWebhook.from_url"
        $webhook_send = "webhook.send"
        $socket_gethostname = "socket.gethostname"
        $socket_gethostbyname = "socket.gethostbyname"
        $discord_url = /https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/

    condition:
        all of ($discord_webhook, $webhook_send, $socket_gethostname, $socket_gethostbyname) and
        $discord_url
}