rule CookieValidation_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects validation of stolen cookies and exfiltration of data to a Discord webhook."
        confidence = 92
        severity = 88
    strings:
        $check_cookie = "CheckCookie"
        $webhook_post = "requests.post"
        $valid_cookie = "Valid Cookie"
        $dead_cookie = "dead cookie"
        $cookie_expired = "cookie is expired"
    condition:
        all of ($check_cookie, $webhook_post) and any of ($valid_cookie, $dead_cookie, $cookie_expired)
}