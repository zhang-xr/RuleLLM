rule Android_Telegram_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Android image exfiltration via Telegram API"
        confidence = 90
        severity = 85
        reference = "Analyzed code segment"
    
    strings:
        $bot_url = "https://api.telegram.org/bot" ascii wide
        $send_doc = "sendDocument" ascii wide
        $sdcard_path1 = "/storage/emulated/0/DCIM/Screenshots/" ascii wide
        $sdcard_path2 = "/storage/emulated/0/DCIM/Camera/" ascii wide
        $image_exts = /\.(jpg|jpeg|png)['"]/ ascii wide
        $telegram_token = /[0-9]{9,10}:[A-Za-z0-9_-]{35}/ ascii wide
    
    condition:
        all of ($bot_url, $send_doc) and 
        (1 of ($sdcard_path1, $sdcard_path2)) and 
        $image_exts and 
        $telegram_token
}