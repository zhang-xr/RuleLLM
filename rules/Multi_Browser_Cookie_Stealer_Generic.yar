rule Multi_Browser_Cookie_Stealer_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects multi-browser cookie stealing functionality with exfiltration"
        confidence = 90
        severity = 85
    strings:
        $firefox = "browser_cookie3.firefox" ascii wide
        $chrome = "browser_cookie3.chrome" ascii wide
        $edge = "browser_cookie3.edge" ascii wide
        $opera = "browser_cookie3.opera" ascii wide
        $chromium = "browser_cookie3.chromium" ascii wide
        $webhook_post = "requests.post" ascii wide
    condition:
        3 of ($firefox, $chrome, $edge, $opera, $chromium) and 
        $webhook_post
}