rule Malicious_Python_Setup_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with custom install commands that use Discord webhooks for data exfiltration."
        confidence = 90
        severity = 80
    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $webhook = "Webhook.from_url"
        $aiohttp = "aiohttp.ClientSession"
        $send_data = "await webhook.send"
    condition:
        all of ($custom_install, $webhook, $aiohttp, $send_data)
}