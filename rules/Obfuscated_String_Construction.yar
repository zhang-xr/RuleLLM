rule Obfuscated_String_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated string construction using chr(int(...))"
        confidence = 80
        severity = 70

    strings:
        $chr_int_pattern = /chr\(int\([^)]+\)\)/
        $join_pattern = /"".join\(/

    condition:
        $chr_int_pattern and 
        $join_pattern
}