rule Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects webhook URLs used for data exfiltration in Python scripts"
        confidence = 85
        severity = 80

    strings:
        $webhook_url = /https?:\/\/webhook\.site\/[a-f0-9\-]+/

    condition:
        $webhook_url
}