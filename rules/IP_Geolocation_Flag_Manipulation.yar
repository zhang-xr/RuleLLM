rule IP_Geolocation_Flag_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects code using IP geolocation APIs and country flag manipulation"
        confidence = 80
        severity = 85

    strings:
        $ip_api = "http://ip-api.com/line/?fields=" ascii wide
        $country_code = "countryCode" ascii wide
        $flag_manipulation = /chr\(int\(ord\([^\)]+\)\) \+ 127397\)/ ascii wide

    condition:
        all of ($ip_api, $country_code) and 
        $flag_manipulation
}