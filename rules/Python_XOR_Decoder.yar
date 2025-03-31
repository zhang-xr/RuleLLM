rule Python_XOR_Decoder {
    meta:
        author = "RuleLLM"
        description = "Detects XOR decoding patterns in Python code"
        confidence = "85"
        severity = "90"
    strings:
        $xor_pattern1 = /[\w\d]+ = \"[^\"]+\"/
        $xor_pattern2 = /[\w\d]+ = len\([\w\d]+\)/
        $xor_pattern3 = /for [\w\d]+ in range\([\w\d]+\):/
        $xor_pattern4 = /chr\(ord\([\w\d]+\[[\w\d]+\]\) \^/
    condition:
        3 of them
}