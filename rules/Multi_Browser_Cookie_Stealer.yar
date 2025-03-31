rule Multi_Browser_Cookie_Stealer {
    meta:
        author = "RuleLLM"
        description = "Detects multi-browser cookie stealing targeting Roblox"
        confidence = 90
        severity = 85
    strings:
        $browser_patterns = /browser_cookie3\.(firefox|chrome|edge|opera)/
        $roblox_domain = "roblox.com"
        $cookie_loop = /for cookie in cookies/
        $cookie_check = "if cookie.name =="
    condition:
        2 of ($browser_patterns) and 
        $roblox_domain and 
        $cookie_loop and 
        $cookie_check
}