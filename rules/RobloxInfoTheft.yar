rule RobloxInfoTheft {
    meta:
        author = "RuleLLM"
        description = "Detects theft of Roblox account information including cookies, IP address, and profile details."
        confidence = 90
        severity = 85
    strings:
        $roblox_cookie = "roblox_cookie"
        $ip_address = "ip_address"
        $roblox_profile = "roblox_profile"
        $rolimons = "rolimons"
        $robux_balance = "RobuxBalance"
        $creation_date = "CreationDate"
    condition:
        all of them
}