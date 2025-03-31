rule Suspicious_Base64_Zlib_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using base64 and zlib to decode and decompress a payload."
        confidence = 95
        severity = 90

    strings:
        $base64_decode = "base64.b64decode"
        $zlib_decompress = "zlib.decompress"
        $codecs_decode = "codecs.decode"
        $large_encoded_string = /[\w\W]{500,}/

    condition:
        all of ($base64_decode, $zlib_decompress, $codecs_decode) and $large_encoded_string
}