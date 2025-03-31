rule Malicious_Python_Package_Discord_Cookie_Extraction {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with potential Discord webhook integration and cookie extraction capabilities"
        confidence = 95
        severity = 90

    strings:
        $s1 = "browser_cookie3" ascii wide
        $s2 = "discord_webhook" ascii wide
        $s3 = "winregistry" ascii wide
        $s4 = "pyautogui" ascii wide
        $s5 = "getmac" ascii wide

    condition:
        all of ($s1, $s2, $s3) and
        1 of ($s4, $s5)
}