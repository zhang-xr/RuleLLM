rule Suspicious_Ngrok_URL {
    meta:
        author = "RuleLLM"
        description = "Detects the use of suspicious Ngrok URLs for data exfiltration"
        confidence = 90
        severity = 85

    strings:
        $ngrok_url = /https?:\/\/[a-f0-9]+\.ngrok\.(app|io)/  // Matches Ngrok URLs

    condition:
        $ngrok_url and
        filesize < 10KB
}