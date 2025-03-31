rule Telegram_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the use of Telegram bot tokens and chat IDs for data exfiltration"
        confidence = 95
        severity = 90
    strings:
        $telegram_token = /[0-9]{10}:[A-Za-z0-9_-]{35}/
        $chat_id = /-[0-9]{9,}/
    condition:
        any of them
}