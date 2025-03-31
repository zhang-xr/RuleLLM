rule Telegram_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code using Telegram API for data exfiltration"
        confidence = 85
        severity = 90

    strings:
        $telegram_bot = "https://api.telegram.org/bot" ascii wide
        $send_message = "sendMessage" ascii wide
        $send_document = "sendDocument" ascii wide
        $chat_id = "chat_id" ascii wide

    condition:
        all of ($telegram_bot, $send_message, $chat_id) or 
        all of ($telegram_bot, $send_document, $chat_id)
}