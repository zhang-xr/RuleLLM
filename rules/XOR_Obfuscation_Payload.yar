rule XOR_Obfuscation_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects XOR-based payload obfuscation patterns in Python code"
        confidence = 85
        severity = 80
    
    strings:
        $xor_pattern1 = /chr\([^\)]+\s*\^\s*[^\)]+\)/
        $xor_pattern2 = /\[x\s*\^\s*t\s+for\s+x\s*,\s*t\s+in\s+zip\(/
        $bytes_fromhex = "bytes.fromhex("
        $hashlib_import = "import hashlib"
        $sha3_usage = "hashlib.sha3_512("
    
    condition:
        all of ($xor_pattern1, $bytes_fromhex) and 
        any of ($xor_pattern2, $hashlib_import, $sha3_usage)
}