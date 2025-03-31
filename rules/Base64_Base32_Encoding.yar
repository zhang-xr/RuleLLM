rule Base64_Base32_Encoding {
    meta:
        author = "RuleLLM"
        description = "Detects the use of Base64 and Base32 encoding"
        confidence = 75
        severity = 70

    strings:
        $b64encode = "b64encode"
        $b32encode = "b32encode"
        $base64_import = "from base64 import b64encode"
        $base32_import = "from base64 import b32encode"

    condition:
        any of ($b64encode, $b32encode, $base64_import, $base32_import)
}