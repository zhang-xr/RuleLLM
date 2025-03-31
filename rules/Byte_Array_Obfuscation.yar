rule Byte_Array_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects byte array obfuscation patterns commonly used in malicious scripts"
        confidence = 85
        severity = 80
        
    strings:
        $byte_array1 = "VAR1 = bytes(["
        $byte_array2 = "VAR2 = bytes(["
        $byte_array3 = "VAR3 = bytes(["
        $xor_pattern = "b ^ k"
        $stream_gen = "def gen("
        
    condition:
        all of ($byte_array1, $byte_array2, $byte_array3) and
        1 of ($xor_pattern, $stream_gen)
}