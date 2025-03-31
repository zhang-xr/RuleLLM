rule Telegram_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code using Telegram API to exfiltrate files from specific directories"
        confidence = "95"
        severity = "90"
    strings:
        $telegram_api = "https://api.telegram.org/bot"
        $send_document = "sendDocument"
        $sdcard_path1 = "/storage/emulated/0/DCIM/Screenshots/"
        $sdcard_path2 = "/storage/emulated/0/DCIM/Camera/"
        $image_extensions1 = ".jpg"
        $image_extensions2 = ".jpeg"
        $image_extensions3 = ".png"
        $requests_session = "requests.session()"
    condition:
        all of ($telegram_api, $send_document, $requests_session) and 
        (1 of ($sdcard_path1, $sdcard_path2)) and 
        (1 of ($image_extensions1, $image_extensions2, $image_extensions3))
}