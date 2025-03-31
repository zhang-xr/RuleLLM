rule PyCrypter_XOR_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects XOR-based code obfuscation in Python scripts"
        confidence = 90
        severity = 85
    strings:
        $xor_loop = "chr(ord(current_string) ^ ord(current_key))"
        $key_generation = "key = key + str(random.randint(0, 9))"
        $eval_compile = "eval(compile(oIoeaTEAcvpae, '<string>', 'exec'))"
        $output_string = "output_string += chr(ord(current_string) ^ ord(current_key))"
    condition:
        3 of them
}