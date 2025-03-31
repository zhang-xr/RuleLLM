rule Python_ObfuscatedCodeExecution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code execution patterns in Python"
        confidence = 90
        severity = 85
        reference = "XOR decryption with eval/compile execution"
    
    strings:
        $xor_loop = /for [a-zA-Z0-9_]+ in range\(len\([a-zA-Z0-9_]+\)\):/
        $chr_ord = /chr\(ord\([a-zA-Z0-9_]+\)/
        $eval_compile = "eval(compile("
        $long_num = /\b\d{10,}\b/  // Matches long numeric strings
        
    condition:
        all of ($xor_loop, $chr_ord, $eval_compile) or
        ($eval_compile and $long_num)
}