rule Ngrok_URL_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of Ngrok URLs in code, often used for malicious exfiltration"
        confidence = 95
        severity = 90

    strings:
        $ngrok_url = /https?:\/\/[a-f0-9]{12}\.ngrok\.(io|app)/ ascii wide

    condition:
        $ngrok_url
}