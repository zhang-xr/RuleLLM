rule Roblox_Cookie_Stealer_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects generic Roblox cookie stealer behavior targeting multiple browsers and exfiltrating to Discord"
        confidence = 95
        severity = 90
    strings:
        $browser_cookie3 = "browser_cookie3" ascii wide
        $roblox_security = ".ROBLOSECURITY" ascii wide
        $webhook_url = /https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+/ ascii wide
        $requests_post = "requests.post" ascii wide
        $ip_check = "api.ipify.org" ascii wide
        $roblox_api = "roblox.com/mobileapi/userinfo" ascii wide
        $os_system = "os.system" ascii wide
    condition:
        all of ($browser_cookie3, $roblox_security, $requests_post) and 
        2 of ($webhook_url, $ip_check, $roblox_api, $os_system)
}