rule Sensitive_Files_Telegram_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the collection of sensitive files and their exfiltration via Telegram"
        confidence = 95
        severity = 90
    strings:
        $exodus_path = "appdata\\roaming\\exodus"
        $wallet_files = /exodus\.(conf\.json|wallet\\[a-z]+\.(seco|json))/
        $telegram_token = /[0-9]{10}:[A-Za-z0-9_-]{35}/
        $chat_id = /-[0-9]{9,}/
    condition:
        all of ($exodus_path, $wallet_files, $telegram_token, $chat_id)
}