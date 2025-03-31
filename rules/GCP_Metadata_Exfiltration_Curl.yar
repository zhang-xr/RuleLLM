rule GCP_Metadata_Exfiltration_Curl {
    meta:
        author = "RuleLLM"
        description = "Detects GCP metadata exfiltration via curl in Python scripts"
        confidence = 95
        severity = 90

    strings:
        $gcp_metadata = "metadata.google.internal"
        $curl_command = /curl\s+-H\s+'Metadata-Flavor:\s+Google'/
        $post_request = /curl\s+-X\s+POST\s+-d\s+'[^']+'\s+https?:\/\/[^\s]+/
        $os_system = "os.system"

    condition:
        all of them
}