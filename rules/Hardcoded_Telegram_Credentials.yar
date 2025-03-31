rule Hardcoded_Telegram_Credentials {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded Telegram bot token and chat ID"
        confidence = "90"
        severity = "85"
    strings:
        $bot_token = /[0-9]{10}:[a-zA-Z0-9_-]{35}/
        $chat_id = /[0-9]{10}/
    condition:
        any of them
}