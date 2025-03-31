rule Roblox_Account_Info_Stealer_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects Roblox account information gathering with exfiltration"
        confidence = 90
        severity = 85
    strings:
        $roblox_api = "roblox.com/mobileapi/userinfo" ascii wide
        $get_rap = "GetRAP" ascii wide
        $get_age = "GetAge" ascii wide
        $creation_date = "CreationDate" ascii wide
        $headshot = "GetHeadshot" ascii wide
        $webhook_post = "requests.post" ascii wide
    condition:
        $roblox_api and 
        2 of ($get_rap, $get_age, $creation_date, $headshot) and 
        $webhook_post
}