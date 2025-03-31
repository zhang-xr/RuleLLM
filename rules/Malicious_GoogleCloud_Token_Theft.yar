rule Malicious_GoogleCloud_Token_Theft {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to steal Google Cloud metadata service tokens."
        confidence = 90
        severity = 95
    strings:
        $metadata_url = "metadata.google.internal/computeMetadata/v1/instance/service-accounts"
        $curl_command = /curl\s+-H\s+'Metadata-Flavor:\s+Google'/
        $webhook_url = /https?:\/\/[^\s]+\/c100b39f-8d06-40c4-bc5f-64e251fcc6ad/
        $os_system = "os.system"
    condition:
        all of them
}