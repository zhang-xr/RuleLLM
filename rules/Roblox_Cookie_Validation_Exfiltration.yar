rule Roblox_Cookie_Validation_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that validates and exfiltrates Roblox cookies"
        confidence = 90
        severity = 95

    strings:
        $check_cookie = "CheckCookie" ascii
        $valid_cookie = "Valid Cookie" ascii
        $webhook_post = "requests.post(url=webhookk" ascii
        $cookie_expired = "cookie is expired" ascii
        $roblox_security = ".ROBLOSECURITY" ascii

    condition:
        all of them and
        filesize < 10KB
}