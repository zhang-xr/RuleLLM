rule Python_GoogleCloudMetadataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to exfiltrate Google Cloud metadata using curl"
        confidence = 90
        severity = 80

    strings:
        $curl_metadata = /curl.*-H.*Metadata-Flavor: Google.*http:\/\/metadata\.google\.internal/
        $webhook_url = /https?:\/\/[^\s]+webhook\.site[^\s]+/
        $os_system = "os.system"

    condition:
        all of them and filesize < 10KB
}