rule Suspicious_Python_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python imports commonly used in credential-stealing malware."
        confidence = 85
        severity = 75

    strings:
        $browser_cookie3 = "browser_cookie3"
        $discordwebhook = "discordwebhook"
        $robloxpy = "robloxpy"
        $requests = "requests"

    condition:
        any of ($browser_cookie3, $discordwebhook, $robloxpy, $requests)
}