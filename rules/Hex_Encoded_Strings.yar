rule Hex_Encoded_Strings {
    meta:
        author = "RuleLLM"
        description = "Detects hex-encoded strings in Python code, often used for obfuscation."
        confidence = 80
        severity = 70

    strings:
        $hex_string = /\\x[0-9a-f]{2}/

    condition:
        $hex_string
}