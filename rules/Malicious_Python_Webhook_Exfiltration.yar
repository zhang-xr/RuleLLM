rule Malicious_Python_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that exfiltrates system data to a webhook URL"
        confidence = 90
        severity = 80

    strings:
        $webhook_url = "https://webhook.site/"
        $ipify_url = "https://api.ipify.org"
        $platform_node = "platform.node()"
        $platform_system = "platform.system()"
        $requests_get = "requests.get"

    condition:
        all of ($webhook_url, $ipify_url, $platform_node, $platform_system, $requests_get)
}