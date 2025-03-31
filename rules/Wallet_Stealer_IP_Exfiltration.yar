rule Wallet_Stealer_IP_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects wallet stealer malware that exfiltrates IP information"
        confidence = 80
        severity = 85
    strings:
        $ip_api = "http://ip-api.com/line/?fields=query" ascii wide
        $country_code = "http://ip-api.com/line/?fields=countryCode" ascii wide
        $requests = "requests.get" ascii wide
        $telegram_token = "https://api.telegram.org/bot" ascii wide
    condition:
        all of them
}