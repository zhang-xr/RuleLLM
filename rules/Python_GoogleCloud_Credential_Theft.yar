rule Python_GoogleCloud_Credential_Theft {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts attempting to steal Google Cloud credentials via metadata service"
        confidence = 90
        severity = 95
        reference = "Analyzed code segment"
    
    strings:
        $metadata_url = "http://metadata.google.internal/computeMetadata/v1/"
        $webhook_url = "https://webhook.site/"
        $os_system = "os.system("
        $curl_cmd = "curl"
        $token_var = "access_token="
        $custom_command = "def custom_command():"
        $custom_install = "class CustomInstallCommand"
        $custom_develop = "class CustomDevelopCommand"
    
    condition:
        filesize < 10KB and
        4 of them and
        all of ($metadata_url, $webhook_url, $os_system) and
        $custom_command in (0..100)
}