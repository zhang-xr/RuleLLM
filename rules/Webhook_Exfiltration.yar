rule Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code attempting to exfiltrate data to a webhook URL."
        confidence = 80
        severity = 85
    strings:
        $webhook_domain = "webhook.site"
        $curl_post = /curl\s+-X\s+POST\s+-d\s+/
        $http_post = /POST\s+-d\s+/
    condition:
        ($webhook_domain and $curl_post) or ($webhook_domain and $http_post)
}