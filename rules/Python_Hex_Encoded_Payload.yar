rule Python_Hex_Encoded_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python malware with hex-encoded payloads"
        confidence = 95
        severity = 90

    strings:
        $hex_payload = /b'\\x[0-9a-fA-F]{2,}'/

    condition:
        $hex_payload
}