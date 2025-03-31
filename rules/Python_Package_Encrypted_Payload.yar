rule Python_Package_Encrypted_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with encrypted payload execution patterns"
        confidence = 90
        severity = 85
        reference = "Fernet encrypted payload execution"
    
    strings:
        $fernet_key = /Fernet\(b'[A-Za-z0-9+\/=]{44}'\)/
        $encrypted_payload = /decrypt\(b'[A-Za-z0-9+\/=]{40,}'\)/
        $exec_pattern = "exec("
    
    condition:
        all of them and 
        filesize < 15KB
}