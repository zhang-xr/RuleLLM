rule Suspicious_Python_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts importing libraries commonly used for credential theft."
        confidence = 95
        severity = 90

    strings:
        $browser_cookie3 = "browser_cookie3"
        $discordwebhook = "discordwebhook"
        $robloxpy = "robloxpy"
        $requests = "requests"

    condition:
        any of them and
        filesize < 50KB
}