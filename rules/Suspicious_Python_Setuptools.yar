rule Suspicious_Python_Setuptools {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setuptools configurations with missing author info and unusual package names"
        confidence = 70
        severity = 50
    strings:
        $setup = "setup("
        $missing_author = /author\s*=\s*["']{2}/
        $missing_email = /author_email\s*=\s*["']{2}/
        $unusual_name = /name\s*=\s*['"][a-zA-Z0-9_]{10,}['"]/
        $browser_cookie3 = "browser_cookie3"
        $discordwebhook = "discordwebhook"
        $robloxpy = "robloxpy"
        $requests = "requests"
    condition:
        all of ($setup, $missing_author, $missing_email) and
        any of ($unusual_name, $browser_cookie3, $discordwebhook, $robloxpy, $requests)
}