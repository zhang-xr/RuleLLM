rule Ngrok_URL_Detection {
    meta:
        author = "RuleLLM"
        description = "Detects Ngrok URLs commonly used in malicious exfiltration"
        confidence = 95
        severity = 90

    strings:
        $ngrok_url = /https:\/\/[a-f0-9]{12}\.ngrok\.app\// ascii wide

    condition:
        $ngrok_url
}