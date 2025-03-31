rule Python_XOR_String_Decoder {
    meta:
        author = "RuleLLM"
        description = "Detects XOR-based string decoding patterns in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $xor_decode1 = "''.join(chr(b ^ k) for b, k in zip("
        $xor_decode2 = "for b, k in zip(buf, function1)"
        $xor_decode3 = "yield b ^ k"
        $xor_decode4 = "bytes([next(function) for _ in range"
    condition:
        2 of ($xor_decode*) and 
        filesize < 15KB
}