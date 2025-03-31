rule Android_Telegram_Credentials {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded Telegram bot credentials"
        confidence = 95
        severity = 90
        reference = "Analyzed code segment"
    
    strings:
        $token_pattern = /[0-9]{9,10}:[A-Za-z0-9_-]{35}/ ascii wide
        $chat_id = /['"][0-9]{9,10}['"]/ ascii wide
    
    condition:
        $token_pattern and $chat_id and 
        #token_pattern < 200 and 
        #chat_id < 200
}