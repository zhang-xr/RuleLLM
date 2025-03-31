rule Python_EncryptedPayloadExecution {
    meta:
        author = "RuleLLM"
        description = "Detects encrypted payload execution patterns in Python code"
        confidence = 90
        severity = 95
    strings:
        $fernet_init = "Fernet("
        $decrypt_call = ".decrypt("
        $exec_cmd = /exec\s*\(/
    condition:
        all of them and filesize < 10KB
}