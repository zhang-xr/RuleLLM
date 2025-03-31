rule Suspicious_Ngrok_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious ngrok.io URLs commonly used in malicious payloads"
        confidence = 85
        severity = 80
    strings:
        $ngrok_pattern = /https:\/\/[a-z0-9]{12}\.ngrok\.(io|app|com|net|org)/
    condition:
        $ngrok_pattern
}