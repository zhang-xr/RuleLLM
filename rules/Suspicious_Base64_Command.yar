rule Suspicious_Base64_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded commands in Python scripts"
        confidence = 85
        severity = 75

    strings:
        $b64decode = "base64.b64decode"
        $b64_encoded = /[A-Za-z0-9+\/]{20,}={0,2}/

    condition:
        $b64decode and $b64_encoded
}