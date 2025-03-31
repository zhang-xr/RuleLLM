rule Roblox_Info_Stealer {
    meta:
        author = "RuleLLM"
        description = "Detects Roblox account information stealer"
        confidence = 92
        severity = 88
    strings:
        $info_endpoints = /robloxpy\.User\.(External|Friends)/
        $robux_check = "RobuxBalance"
        $creation_date = "CreationDate"
        $headshot = "GetHeadshot"
        $ip_check = "api.ipify.org"
    condition:
        3 of ($info_endpoints) and 
        ($robux_check or $creation_date or $headshot) and 
        $ip_check
}