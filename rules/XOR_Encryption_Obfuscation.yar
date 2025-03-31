rule XOR_Encryption_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects XOR encryption and obfuscation techniques in Python scripts"
        confidence = 85
        severity = 75

    strings:
        $xor_pattern = /chr\(ord\([^)]+\) \^ ord\([^)]+\)\)/
        $eval_compile = "eval(compile"
        $random_key_generation = "random.randint(0, 9)"

    condition:
        all of them
}