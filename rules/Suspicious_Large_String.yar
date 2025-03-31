rule Suspicious_Large_String {
    meta:
        author = "RuleLLM"
        description = "Detects large, seemingly random strings that may contain encoded or compressed payloads."
        confidence = 90
        severity = 85

    strings:
        $large_string = /[\w\W]{500,}/
        $base64_import = "base64"
        $codecs_import = "codecs"
        $zlib_import = "zlib"

    condition:
        $large_string and any of ($base64_import, $codecs_import, $zlib_import)
}