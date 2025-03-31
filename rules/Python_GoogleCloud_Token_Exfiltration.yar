rule Python_GoogleCloud_Token_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code exfiltrating Google Cloud access tokens via webhook"
        confidence = 95
        severity = 90
    strings:
        $google_metadata = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts"
        $metadata_flavor = "Metadata-Flavor: Google"
        $webhook_pattern = /https?:\/\/[^\s"]+\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/
        $curl_command = "curl -H"
        $os_system = "os.system("
    condition:
        all of them
}