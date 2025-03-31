rule Malicious_Python_Package_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages based on behavioral patterns"
        confidence = 85
        severity = 75
        reference = "Analysis of malicious Python packages"
        
    strings:
        $cookie_stealer = "browser_cookie3"
        $discord_webhook = "discordwebhook"
        $roblox_interaction = "robloxpy"
        $http_request = "requests"
        $suspicious_setup = /setup\(\s*name\s*=\s*['"][a-z]{10,}['"]/
        
    condition:
        ($cookie_stealer and $discord_webhook) or
        ($roblox_interaction and $http_request) and
        $suspicious_setup
}