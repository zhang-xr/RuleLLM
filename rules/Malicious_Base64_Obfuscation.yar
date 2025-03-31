rule Malicious_Base64_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded payloads commonly used in malware obfuscation"
        confidence = 90
        severity = 80

    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/

    condition:
        $base64_pattern
}