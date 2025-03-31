rule Roblox_Cookie_Stealer_DiscordWebhook {
    meta:
        author = "RuleLLM"
        description = "Detects a Roblox cookie stealer that sends stolen cookies to a Discord webhook using browser_cookie3 and requests.post."
        confidence = 95
        severity = 90
    strings:
        $webhook_pattern = /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9-_]+/
        $roblox_cookie = ".ROBLOSECURITY"
        $browser_cookie3 = "browser_cookie3"
        $robloxpy = "robloxpy"
        $cookie_check = "CheckCookie"
        $webhook_post = "requests.post(url=webhookk"
    condition:
        all of them
}