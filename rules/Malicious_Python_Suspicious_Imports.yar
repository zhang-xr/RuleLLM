rule Malicious_Python_Suspicious_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python module imports often used in malicious scripts."
        confidence = 85
        severity = 75

    strings:
        $browser_cookie3 = "browser_cookie3"
        $discordwebhook = "discordwebhook"
        $robloxpy = "robloxpy"
        $requests = "requests"

    condition:
        2 of ($browser_cookie3, $discordwebhook, $robloxpy, $requests)
}