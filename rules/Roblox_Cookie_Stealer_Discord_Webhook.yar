rule Roblox_Cookie_Stealer_Discord_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based Roblox cookie stealer that exfiltrates data to Discord webhook"
        confidence = 90
        severity = 95

    strings:
        $browser_cookie3 = "browser_cookie3" ascii
        $robloxpy = "robloxpy" ascii
        $discordwebhook = "discordwebhook" ascii
        $roblox_security = ".ROBLOSECURITY" ascii
        $webhook_url = /https:\/\/canary\.discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/ ascii
        $cookie_logger = "cookieLogger()" ascii
        $ip_address = "api.ipify.org" ascii

    condition:
        all of them and
        filesize < 10KB
}