rule Malicious_Python_Hex_Escapes {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using hex escape sequences for obfuscation"
        confidence = 90
        severity = 85

    strings:
        $hex_escape = /\\x[0-9a-fA-F]{2}/

    condition:
        3 of them
}