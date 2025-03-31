rule Malicious_Python_Package_Metadata_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages attempting to exfiltrate Google Cloud metadata tokens"
        confidence = 90
        severity = 95
    strings:
        $metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        $curl_command = /curl\s+-H\s+'Metadata-Flavor:\s+Google'/
        $exfil_url = /https?:\/\/[^\s\/]+\/hellofrompip/
    condition:
        all of them
}