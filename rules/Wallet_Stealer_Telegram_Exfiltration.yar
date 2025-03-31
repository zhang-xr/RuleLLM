rule Wallet_Stealer_Telegram_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects wallet stealer malware that exfiltrates data via Telegram API"
        confidence = 90
        severity = 95
    strings:
        $telegram_token = "https://api.telegram.org/bot" ascii wide
        $chat_id = "chat_id" ascii wide
        $send_message = "sendMessage" ascii wide
        $send_document = "sendDocument" ascii wide
        $zipfile = "ZipFile" ascii wide
        $wallet_paths = /C:\\Users\\.+\\appdata\\roaming\\exodus\\/ ascii wide
        $getuser = "getpass.getuser()" ascii wide
        $requests = "requests.post" ascii wide
    condition:
        all of them
}