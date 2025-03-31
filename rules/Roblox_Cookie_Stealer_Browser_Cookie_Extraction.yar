rule Roblox_Cookie_Stealer_Browser_Cookie_Extraction {
    meta:
        author = "RuleLLM"
        description = "Detects the browser cookie extraction functionality targeting Roblox cookies from multiple browsers."
        confidence = 90
        severity = 85
    strings:
        $browser_cookie3 = "browser_cookie3"
        $roblox_cookie = ".ROBLOSECURITY"
        $firefox = "browser_cookie3.firefox"
        $chrome = "browser_cookie3.chrome"
        $edge = "browser_cookie3.edge"
        $opera = "browser_cookie3.opera"
        $chromium = "browser_cookie3.chromium"
    condition:
        3 of them
}