rule Python_ObfuscatedXorPayload {
    meta:
        author = "RuleLLM"
        description = "Detects XOR-based payload obfuscation in Python code"
        confidence = "92"
        severity = "88"
    
    strings:
        $xor_decrypt = /for [a-zA-Z0-9_]+ in range\([a-zA-Z0-9_]+\):[\s\S]{1,200}chr\(ord\([a-zA-Z0-9_]+\) \^ ord\([a-zA-Z0-9_]+\)\)/
        $long_numeric = /\d{50,}/
        $eval_compile = "eval(compile("
    
    condition:
        $xor_decrypt and 
        ($long_numeric or $eval_compile)
}