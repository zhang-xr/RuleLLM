rule SHA3_512_Hash_Generation {
    meta:
        author = "RuleLLM"
        description = "Detects the use of SHA3-512 hash generation for cryptographic purposes"
        confidence = "75"
        severity = "75"
    
    strings:
        $hashlib = "hashlib.sha3_512(v).digest()"
        $hash_split = "hsh[0:32], hsh[32:]"
    
    condition:
        all of them
}