rule Suspicious_Webhook_URL {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of a specific webhook URL used for potential C2 communication"
        confidence = 90
        severity = 80
    strings:
        $webhook_url = "https://webhook.site/baf67bd8-bf43-41ae-8af2-4a0fb906f90d/analytics"
    condition:
        $webhook_url
}