rule Roblox_Account_Info_Gathering {
    meta:
        author = "RuleLLM"
        description = "Detects code that gathers Roblox account information including RAP, friends, and account age"
        confidence = 85
        severity = 90

    strings:
        $get_rap = "GetRAP" ascii
        $get_friends = "GetCount" ascii
        $get_age = "GetAge" ascii
        $creation_date = "CreationDate" ascii
        $headshot = "GetHeadshot" ascii
        $roblox_profile = "roblox.com/users" ascii
        $rolimons = "rolimons.com/player" ascii

    condition:
        4 of them and
        filesize < 10KB
}