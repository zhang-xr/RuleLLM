rule Path_Byte_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects path and byte manipulation patterns used in malicious code"
        confidence = "70"
        severity = "70"
    
    strings:
        $path_bytes = "path_bytes = str(path).encode(\"utf-8\")"
        $to_hash = "to_hash = RG[4]  + path_bytes"
        $stream = "stream = gen(to_hash)"
        $first_n_bytes = "first_n_bytes = bytes([next(stream) for _ in range(32)])"
    
    condition:
        all of them
}