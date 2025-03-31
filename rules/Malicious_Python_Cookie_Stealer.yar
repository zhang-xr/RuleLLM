rule Malicious_Python_Cookie_Stealer {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages attempting to steal browser cookies"
        confidence = 95
        severity = 90
    strings:
        $cookie_lib = "browser_cookie3"
        $webhook_lib = "discordwebhook"
        $http_lib = "requests"
    condition:
        all of them
}