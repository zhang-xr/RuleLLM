rule CookieStealer_Roblox_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects generic cookie stealing targeting Roblox accounts using browser_cookie3 and exfiltration via webhook"
        confidence = 95
        severity = 90
    
    strings:
        $browser_cookie3 = "browser_cookie3"
        $roblox_security = ".ROBLOSECURITY"
        $webhook_url = /webhookk\s*=\s*['"][^'"]+['"]/
        $cookie_check = "robloxpy.Utils.CheckCookie"
        $user_info = "https://www.roblox.com/mobileapi/userinfo"
    
    condition:
        all of them and 
        #browser_cookie3 >= 3 and 
        filesize < 100KB
}