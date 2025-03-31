rule Obfuscated_Strings_Python {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated strings in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $base64_encoded = /[A-Za-z0-9+\/]{20,}={0,2}/ nocase
        $zlib_compressed = /\x78[\x01\x9C\xDA]/
        $codecs_usage = /codecs\.\w+\(.*\)/ nocase
    condition:
        any of them
}