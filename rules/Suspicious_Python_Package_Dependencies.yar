rule Suspicious_Python_Package_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package dependencies"
        confidence = 80
        severity = 70
        
    strings:
        $dep1 = "browser_cookie3"
        $dep2 = "discordwebhook"
        $dep3 = "robloxpy"
        $dep4 = "requests"
        
    condition:
        3 of ($dep*)
}