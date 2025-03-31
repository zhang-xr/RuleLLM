rule MultiBrowser_CookieLogger {
    meta:
        author = "RuleLLM"
        description = "Detects multi-browser cookie logging functionality targeting specific domains"
        confidence = 92
        severity = 88
    
    strings:
        $cookie_logger = "cookieLogger"
        $browsers = /browser_cookie3\.(firefox|chromium|edge|opera|chrome)/
        $domain_check = /(roblox\.com|otherdomain\.com)/
        $cookie_value = "cookie.value"
    
    condition:
        all of them and 
        #browsers >= 3 and 
        filesize < 100KB
}