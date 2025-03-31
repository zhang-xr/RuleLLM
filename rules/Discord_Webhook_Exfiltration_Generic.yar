rule Discord_Webhook_Exfiltration_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects Discord webhook exfiltration patterns with cookie stealing"
        confidence = 95
        severity = 90
    strings:
        $webhook_url = /https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+/ ascii wide
        $requests_post = "requests.post" ascii wide
        $roblox_security = ".ROBLOSECURITY" ascii wide
        $content_field = /data=\{[^}]*content[^}]*\}/ ascii wide
    condition:
        $webhook_url and 
        $requests_post and 
        ($roblox_security or $content_field)
}