rule Malicious_GoogleCloud_TokenExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that fetches Google Cloud metadata tokens and exfiltrates them to external webhooks."
        confidence = "95"
        severity = "90"

    strings:
        $metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
        $curl_command = /curl\s+-H\s+'Metadata-Flavor:\s+Google'/
        $webhook_url = /https?:\/\/[^\s]+/
        $access_token = /access_token=\$\(curl/

    condition:
        all of them
}