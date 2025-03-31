rule Base64_Obfuscated_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded payloads with suspicious patterns"
        confidence = 85
        severity = 80
        
    strings:
        $base64_pattern = /base64\.b64decode\(/
        $zlib_pattern = /zlib\.decompress\(/
        $codecs_pattern = /codecs\.decode\(/
        $payload_pattern = /[A-Za-z0-9+\/]{40,}/
        
    condition:
        ($base64_pattern and $zlib_pattern) or ($base64_pattern and $codecs_pattern) or ($base64_pattern and $payload_pattern)
}