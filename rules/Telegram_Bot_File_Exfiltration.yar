rule Telegram_Bot_File_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects usage of Telegram Bot API for file exfiltration"
        confidence = 90
        severity = 85
    strings:
        $telegram_api_url = "https://api.telegram.org/bot"
        $send_document = "sendDocument"
        $chat_id = "chat_id"
        $session_post = "session.post"
        $storage_path = "/storage/emulated/0/DCIM/"
    condition:
        all of them
}