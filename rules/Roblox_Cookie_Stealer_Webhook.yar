rule Roblox_Cookie_Stealer_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects Roblox cookie stealer using Discord webhook for exfiltration"
        confidence = 95
        severity = 90
    strings:
        $webhook_pattern = /https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/
        $roblox_cookie = ".ROBLOSECURITY"
        $browser_cookie3 = "browser_cookie3"
        $cookie_check = "robloxpy.Utils.CheckCookie"
        $user_info = "https://www.roblox.com/mobileapi/userinfo"
    condition:
        all of them and 
        filesize < 10KB and 
        #webhook_pattern > 0
}