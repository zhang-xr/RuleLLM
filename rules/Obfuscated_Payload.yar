rule Obfuscated_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated payloads using base64 and zlib"
        confidence = 85
        severity = 90
    strings:
        $base64_decode = "base64.b64decode" nocase
        $zlib_decompress = "zlib.decompress" nocase
        $codecs_decode = "codecs.decode" nocase
        $chr_array = /chr\(\d+\)/
        $join = "join"
    condition:
        ($base64_decode and $zlib_decompress and $codecs_decode) and $chr_array and $join
}