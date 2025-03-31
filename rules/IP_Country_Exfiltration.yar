rule IP_Country_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the use of ip-api.com to exfiltrate IP address and country code"
        confidence = 85
        severity = 80
    strings:
        $ip_api_url = "http://ip-api.com/line/?fields=query"
        $country_code_url = "http://ip-api.com/line/?fields=countryCode"
    condition:
        any of them
}