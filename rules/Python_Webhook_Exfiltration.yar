rule Python_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that uses webhooks to exfiltrate data to a remote server."
        confidence = 95
        severity = 85
    strings:
        $webhook_url = /https?:\/\/webhook\-test\.com\/[a-f0-9]{32}/
        $requests_get = "requests.get("
        $json_parse = ".json()"
        $ip_address = "ip_address"
    condition:
        $webhook_url and all of ($requests_get, $json_parse, $ip_address)
}