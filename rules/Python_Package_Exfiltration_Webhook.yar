rule Python_Package_Exfiltration_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that use curl to exfiltrate data to webhook.site"
        confidence = 90
        severity = 85
    strings:
        $curl = "os.system(\"curl"
        $webhook = "https://webhook.site/"
        $post = "-X POST"
    condition:
        all of them
}