rule Discord_Webhook_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts using Discord webhooks for data exfiltration."
        confidence = 90
        severity = 85

    strings:
        $discord_webhook = /SyncWebhook\.from_url\s*\(\s*['"][^'"]+['"]\s*\)/
        $hostname = "socket.gethostname()"
        $ipaddr = "socket.gethostbyname(hostname)"
        $webhook_send = "webhook.send(content="
        $custom_install = "class CustomInstallCommand(install):"

    condition:
        all of ($discord_webhook, $hostname, $ipaddr, $webhook_send, $custom_install)
}