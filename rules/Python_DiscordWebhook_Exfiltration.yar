rule Python_DiscordWebhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages using Discord webhooks for data exfiltration"
        confidence = 90
        severity = 80
    strings:
        $webhook_url = /https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/ ascii wide
        $webhook_class = "Webhook.from_url" ascii wide
        $async_webhook = "AsyncWebhookAdapter" ascii wide
        $aiohttp = "aiohttp.ClientSession" ascii wide
        $send_content = "await webhook.send(content=" ascii wide
    condition:
        all of them
}