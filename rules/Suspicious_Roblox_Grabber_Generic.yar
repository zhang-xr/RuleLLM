rule Suspicious_Roblox_Grabber_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Roblox grabber behavior with multiple browser cookie extraction attempts and exfiltration"
        confidence = 85
        severity = 80
    strings:
        $browser_types = /browser_cookie3\.(firefox|chromium|edge|opera|chrome)/ ascii wide
        $cookie_check = "if cookie.name == '.ROBLOSECURITY':" ascii wide
        $webhook_post = "requests.post" ascii wide
        $dummy_message = /dummy_message\s*=\s*"Loading\.\.\."/ ascii wide
    condition:
        all of ($browser_types, $cookie_check, $webhook_post) and 
        $dummy_message
}