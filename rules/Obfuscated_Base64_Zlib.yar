rule Obfuscated_Base64_Zlib {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code using Base64 and zlib compression"
        confidence = 90
        severity = 80

    strings:
        $base64 = "base64" ascii
        $zlib = "zlib" ascii
        $obfuscate = "obfuscate" ascii
        $pyobfuscate = "pyobfuscate" ascii

    condition:
        all of them
}