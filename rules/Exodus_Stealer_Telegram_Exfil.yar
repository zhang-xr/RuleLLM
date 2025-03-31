rule Exodus_Stealer_Telegram_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects Exodus wallet stealer using Telegram for exfiltration"
        confidence = 95
        severity = 90
    strings:
        $bot_token = /[0-9]{9,10}:[A-Za-z0-9_-]{35}/ ascii wide
        $chat_id = /chat_id=[\-\d]{4,12}/ ascii wide
        $exodus_paths = /appdata\\roaming\\exodus\\exodus\.wallet/ ascii wide
        $telegram_api = "api.telegram.org/bot" ascii wide
        $wallet_files = /(seed\.seco|passphrase\.json|storage\.seco|twofactor)/ ascii wide
        $ip_api = "ip-api.com" ascii wide
    condition:
        3 of them and filesize < 100KB
}