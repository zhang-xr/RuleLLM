rule Fernet_Decryption_In_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects the use of Fernet decryption in Python setup.py files, often used to execute encrypted payloads."
        confidence = 90
        severity = 85
    strings:
        $fernet_import = /from\s+fernet\s+import\s+Fernet/
        $fernet_decrypt = /Fernet\(.+?\)\.decrypt\(.+?\)/
    condition:
        all of them
}