rule GCP_Metadata_Token_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to exfiltrate GCP metadata access tokens"
        confidence = 90
        severity = 95

    strings:
        $gcp_metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts"
        $metadata_flavor = "Metadata-Flavor: Google"
        $curl_command = /curl\s+-H\s+['"]Metadata-Flavor:\s+Google['"]/
        $webhook_url = /https?:\/\/[^\s]+/
        $post_request = /curl\s+-X\s+POST\s+-d\s+['"]\$[^\s]+['"]/

    condition:
        all of ($gcp_metadata_url, $metadata_flavor, $curl_command) and 
        any of ($webhook_url, $post_request)
}