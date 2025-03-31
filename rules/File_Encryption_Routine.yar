rule File_Encryption_Routine {
    meta:
        author = "RuleLLM"
        description = "Detects file encryption routine in Python code"
        confidence = 80
        severity = 85
    strings:
        $enc_key_gen = "key = key + str(random.randint(0, 9))"
        $xor_enc = "chr(ord(current_string) ^ ord(current_key))"
        $eval_compile = "eval(compile(oIoeaTEAcvpae, '<string>', 'exec'))"
    condition:
        all of them
}