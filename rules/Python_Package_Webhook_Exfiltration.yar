rule Python_Package_Webhook_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages using webhook.site for data exfiltration."
        confidence = 95
        severity = 90

    strings:
        $webhook_domain = "webhook.site" nocase
        $urlopen = "urllib.request.urlopen" nocase
        $data_encode = "urlencode(data).encode()" nocase

    condition:
        all of them and 
        filesize < 10KB
}