rule Encoded_Payload_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects encoded payloads (hex or Base64) that are dynamically executed"
        confidence = 95
        severity = 90

    strings:
        $hex_pattern = /\\x[0-9a-fA-F]{2}/
        $base64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/
        $exec_pattern = "exec"
        $eval_pattern = "eval"

    condition:
        ($hex_pattern or $base64_pattern) and
        any of ($exec_pattern, $eval_pattern)
}