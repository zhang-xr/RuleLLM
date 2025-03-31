rule Base58_JSON_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects Base58 decoding and JSON manipulation, often used to obfuscate malicious payloads."
        confidence = 75
        severity = 65
    strings:
        $base58_decode = "base58.b58decode" wide
        $json_encoder = "MyEncoder" wide
        $remove_bytesio = "remove_bytesio" wide
    condition:
        any of them
}