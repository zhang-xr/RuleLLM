rule Malicious_Python_Encoded_Payload_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects execution of encoded payloads using base64 and dynamic evaluation."
        confidence = 95
        severity = 90

    strings:
        $b64_pattern = /b'[A-Za-z0-9+\/=]+'/
        $exec_call = /exec\s*\(.*\)/
        $decode_call = /decode\s*\(.*\)/

    condition:
        $b64_pattern and ($exec_call or $decode_call)
}