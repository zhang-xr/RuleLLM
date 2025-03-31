rule Python_GoogleMetadataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts attempting to exfiltrate Google Cloud metadata tokens"
        confidence = "95"
        severity = "90"
        
    strings:
        $metadata_url = "metadata.google.internal/computeMetadata/v1/instance/service-accounts" nocase
        $token_cmd = /curl\s+-[Hh]\s+'Metadata-Flavor:\s+Google'/
        $webhook_cmd = /curl\s+-X\s+POST\s+-d\s+'\$[a-zA-Z0-9_]+'\s+https?:\/\//
        $setuptools_hook = /cmdclass\s*=\s*{\s*['"]install['"]\s*:\s*\w+,\s*['"]develop['"]\s*:\s*\w+/s
        
    condition:
        all of them and filesize < 10KB
}