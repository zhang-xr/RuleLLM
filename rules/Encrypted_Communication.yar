rule Encrypted_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects encrypted communication patterns"
        confidence = "80"
        severity = "70"
    
    strings:
        $xor_encrypt = /def\s+xor_encrypt_decrypt/
        $encryption_key = /encryption_key\s*=\s*'[^']+'/
        $encrypted_data = /encrypted_data\s*=\s*xor_encrypt_decrypt/
    
    condition:
        all of them
}