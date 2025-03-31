rule Python_XOR_Loader {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using XOR-based payload loading"
        confidence = 85
        severity = 75
    strings:
        $xor_pattern1 = /chr\(b \^ k\) for b, k in zip/
        $xor_pattern2 = /bytes\(\[b \^ k for b, k in zip/
        $gen_function = "def gen(v: bytes"
        $hashlib = "hashlib.sha3_512"
    condition:
        filesize < 10KB and
        3 of them
}