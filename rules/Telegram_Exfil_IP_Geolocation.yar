rule Telegram_Exfil_IP_Geolocation {
    meta:
        author = "RuleLLM"
        description = "Detects IP geolocation and Telegram exfiltration patterns"
        confidence = 92
        severity = 88
    strings:
        $ip_api = "ip-api.com/line/?fields=" ascii wide
        $country_flag = "chr(int(ord(i)) + 127397" ascii
        $telegram_send = "api.telegram.org/bot" ascii wide
        $send_document = "sendDocument?chat_id=" ascii wide
        $send_message = "sendMessage?chat_id=" ascii wide
    condition:
        3 of them and filesize < 100KB
}