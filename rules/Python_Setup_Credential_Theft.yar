rule Python_Setup_Credential_Theft {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts attempting to steal credentials from Google Cloud Metadata service"
        confidence = "95"
        severity = "90"
    
    strings:
        $metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        $ngrok_pattern = /https:\/\/[\d-]+\.ngrok-free\.app/
        $suspicious_pkg = "youreallydontwantthispackage2131"
        $custom_command = "custom_command"
        $cmd_class1 = "CustomInstallCommand"
        $cmd_class2 = "CustomDevelopCommand"
        $cmd_class3 = "CustomEggInfoCommand"
    
    condition:
        filesize < 20KB and
        all of ($metadata_url, $ngrok_pattern) and
        (3 of ($cmd_class*) or $suspicious_pkg) and
        $custom_command
}