rule Base64_Zlib_Payload_Decoding {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 and zlib usage for decoding and decompressing payloads"
        confidence = 90
        severity = 85

    strings:
        $base64_pattern = "base64.b64decode"
        $zlib_pattern = "zlib.decompress"
        $codecs_pattern = "codecs.decode"

    condition:
        all of them
}