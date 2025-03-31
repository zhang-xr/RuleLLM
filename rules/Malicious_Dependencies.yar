rule Malicious_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with known malicious dependencies."
        confidence = 90
        severity = 80
    strings:
        $browser_cookie3 = "browser_cookie3"
        $discordwebhook = "discordwebhook"
        $robloxpy = "robloxpy"
        $requests = "requests"
    condition:
        any of ($browser_cookie3, $discordwebhook, $robloxpy) 
        and 
        $requests
}