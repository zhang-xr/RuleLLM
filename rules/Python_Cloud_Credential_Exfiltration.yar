rule Python_Cloud_Credential_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of cloud credential exfiltration in Python scripts"
        confidence = 95
        severity = 100
        reference = "Analyzed code segment"
    
    strings:
        $metadata_pattern = /http:\/\/metadata\.[a-z0-9.-]+\/computeMetadata\/v1\//
        $webhook_pattern = /https:\/\/webhook\.[a-z0-9.-]+\//
        $curl_pattern = /curl\s+-[a-zA-Z0-9]+\s+['"][^'"]*['"]/
        $token_pattern = /(access_?token|api_?key|secret)=/
    
    condition:
        filesize < 10KB and
        3 of them and
        $metadata_pattern and $webhook_pattern
}