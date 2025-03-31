rule GCP_Metadata_Service_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects abuse of GCP metadata service to retrieve access tokens"
        confidence = 90
        severity = 80

    strings:
        $metadata_url = "metadata.google.internal/computeMetadata/v1/instance/service-accounts"
        $curl_command = /curl\s+-H\s+'Metadata-Flavor:\s+Google'/
        $access_token = "access_token="

    condition:
        all of them
}