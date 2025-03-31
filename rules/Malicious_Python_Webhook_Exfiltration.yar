rule Malicious_Python_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that exfiltrate data to Discord webhooks during installation."
        confidence = 90
        severity = 80
    strings:
        $discord_webhook = /https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/
        $import_discord = "from discord import Webhook, AsyncWebhookAdapter"
        $import_aiohttp = "import aiohttp"
        $custom_install = "class CustomInstallCommand(install):"
        $generic_author = /author\s*=\s*['\"].*['\"]/
        $generic_url = /url\s*=\s*['\"]https:\/\/github\.com['\"]/
    condition:
        $discord_webhook and 
        ($import_discord or $import_aiohttp) and 
        ($custom_install or $generic_author or $generic_url)
}