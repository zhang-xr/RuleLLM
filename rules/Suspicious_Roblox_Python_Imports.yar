rule Suspicious_Roblox_Python_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python imports commonly used in Roblox cookie stealers"
        confidence = 80
        severity = 85

    strings:
        $import_browser_cookie3 = "import browser_cookie3" ascii
        $import_robloxpy = "import robloxpy" ascii
        $import_discordwebhook = "from discordwebhook import" ascii
        $import_requests = "import requests" ascii

    condition:
        3 of them and
        filesize < 10KB
}