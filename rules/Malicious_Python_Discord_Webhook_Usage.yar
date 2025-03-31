rule Malicious_Python_Discord_Webhook_Usage {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that uses Discord webhooks for data exfiltration"
        confidence = 92
        severity = 90

    strings:
        $discord_webhook = /discord_webhook/ nocase
        $requests_post = /requests\.post\(/ nocase

    condition:
        $discord_webhook and $requests_post
}