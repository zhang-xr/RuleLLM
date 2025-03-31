rule Base64_Zlib_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 and Zlib obfuscation patterns"
        confidence = 95
        severity = 90

    strings:
        $base64_decode = /base64\.b64decode\(.*\)/
        $zlib_decompress = /zlib\.decompress\(.*\)/
        $codecs_decode = /codecs\.decode\(.*\)/

    condition:
        any of ($base64_decode, $zlib_decompress, $codecs_decode)
}