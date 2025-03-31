rule Obfuscated_String_Decryption {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated string decryption patterns in Python scripts"
        confidence = 80
        severity = 75

    strings:
        $xor_decryption = /chr\(ord\([^)]+\) \^ ord\([^)]+\)\)/
        $long_obfuscated_string = /[\x00-\x1F\x7F-\xFF]{50,}/
        $numeric_key = /\d{50,}/

    condition:
        $xor_decryption and ($long_obfuscated_string or $numeric_key)
}