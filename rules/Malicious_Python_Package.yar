rule Malicious_Python_Package {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup with potential data exfiltration capabilities"
        confidence = 85
        severity = 90
        
    strings:
        $setup = "from setuptools import setup, find_packages"
        $cookie = "browser_cookie3"
        $discord = "discordwebhook"
        $roblox = "robloxpy"
        $requests = "requests"
        $empty_author = "author=\"\""
        $empty_email = "author_email=\"\""
        
    condition:
        all of ($setup, $requests) and 
        2 of ($cookie, $discord, $roblox) and
        (1 of ($empty_author, $empty_email))
}