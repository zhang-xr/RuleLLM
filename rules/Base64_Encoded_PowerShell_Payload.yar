rule Base64_Encoded_PowerShell_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded PowerShell payloads in scripts"
        confidence = 95
        severity = 100

    strings:
        $base64_payload = /powershell -WindowStyle Hidden -EncodedCommand [A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        $base64_payload
}