rule Malicious_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that exfiltrate data to a webhook URL"
        confidence = "90"
        severity = "80"

    strings:
        $webhook_url = "https://webhook.site/17c8fbe7-886e-4f2f-8f67-1d104d430d55"
        $webhook_regex = /https:\/\/webhook\.site\/[a-f0-9-]{36}/
        $webhook_domain = "webhook.site"
        $data_exfil_pattern = /Data={platform\.node\(\)}_{platform\.system\(\)_/

    condition:
        ($webhook_url or $webhook_regex or $webhook_domain) and $data_exfil_pattern
}