rule Python_Package_Ngrok_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages using ngrok domains for data exfiltration"
        confidence = 98
        severity = 95
    strings:
        $ngrok_url = /https:\/\/[a-z0-9]{12}\.ngrok\.app\/[a-z0-9_-]+/
        $urlopen = "urllib.request.urlopen"
        $data_encode = "urlencode" nocase
    condition:
        $ngrok_url and 
        any of ($urlopen, $data_encode)
}