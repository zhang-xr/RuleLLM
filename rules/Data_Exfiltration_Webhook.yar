rule Data_Exfiltration_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects exfiltration of data to an external webhook URL"
        confidence = 95
        severity = 90

    strings:
        $webhook_url = "https://webhook.site/"
        $curl_post = /curl\s+-X\s+POST\s+-d/
        $access_token = "access_token="

    condition:
        all of them
}