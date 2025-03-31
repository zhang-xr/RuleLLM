rule Python_Obfuscation_Base64_Zlib {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using Base64 and Zlib for potential obfuscation"
        confidence = 70
        severity = 50

    strings:
        $base64 = "base64.b64decode"
        $zlib = "zlib.decompress"
        $codecs = "codecs.decode"

    condition:
        all of them
}