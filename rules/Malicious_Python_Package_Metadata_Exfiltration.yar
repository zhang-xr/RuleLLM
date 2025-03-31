rule Malicious_Python_Package_Metadata_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup that queries Google Cloud Metadata and exfiltrates access tokens"
        confidence = 95
        severity = 90
    strings:
        $metadata_query = /http:\/\/metadata\.google\.internal\/computeMetadata\/v1\/instance\/service-accounts\//
        $webhook_url = /https:\/\/webhook\.site\/[a-f0-9\-]+/
        $cmdclass = /cmdclass\s*=\s*\{/
        $custom_command = "custom_command()"
    condition:
        all of them and 
        filesize < 10KB  // Limits to small setup.py files
}