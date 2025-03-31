rule Encrypted_Payload_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects execution of encrypted payloads in Python code"
        confidence = 98
        severity = 95
    strings:
        $fernet_key = /Fernet\(b'[A-Za-z0-9+\/=]+'\)/
        $decrypt_call = /\.decrypt\(b'[A-Za-z0-9+\/=]+'\)/
        $exec_call = "exec("
    condition:
        $exec_call and ($fernet_key or $decrypt_call)
}