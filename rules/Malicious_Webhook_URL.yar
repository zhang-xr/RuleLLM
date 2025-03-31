rule Malicious_Webhook_URL {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded webhook URL used for data exfiltration"
        confidence = 90
        severity = 80
    strings:
        $webhook_url = "https://webhook.site/17c8fbe7-886e-4f2f-8f67-1d104d430d55"
    condition:
        $webhook_url
}