rule Suspicious_Roblox_Package {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python packages related to Roblox with potentially malicious intent"
        confidence = "75"
        severity = "65"
    
    strings:
        $roblox = "Roblox"
        $robloxpy = "robloxpy"
        $discordwebhook = "discordwebhook"
        $browser_cookie3 = "browser_cookie3"
    
    condition:
        all of ($roblox, $robloxpy) and
        any of ($discordwebhook, $browser_cookie3)
}