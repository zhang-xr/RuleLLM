rule Python_IPCollection_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts collecting IP information and exfiltrating it"
        confidence = 90
        severity = 85
    strings:
        $ipinfo_url = "https://ipinfo.io"
        $requests_get = "requests.get"
        $base64_encode = "base64.b64encode"
        $remote_url = /https?:\/\/[^\s]+\?/
    condition:
        all of ($ipinfo_url, $requests_get, $base64_encode) and
        1 of ($remote_url)
}