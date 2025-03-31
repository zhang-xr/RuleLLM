rule Roblox_Cookie_Stealer_User_Info_Extraction {
    meta:
        author = "RuleLLM"
        description = "Detects the extraction of user information from a Roblox account using a stolen cookie."
        confidence = 85
        severity = 80
    strings:
        $robloxpy = "robloxpy"
        $user_info = "https://www.roblox.com/mobileapi/userinfo"
        $get_rap = "GetRAP"
        $get_friends = "GetCount"
        $get_age = "GetAge"
        $creation_date = "CreationDate"
    condition:
        3 of them
}