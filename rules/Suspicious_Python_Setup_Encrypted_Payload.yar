rule Suspicious_Python_Setup_Encrypted_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that use Fernet encryption to execute potentially malicious payloads during installation."
        confidence = 90
        severity = 80

    strings:
        $fernet_decrypt = "Fernet("
        $exec_decrypted = "exec(Fernet("
        $setup_class = "class {"
        $cmdclass = "cmdclass="
        $install_override = "def run(self):"
        $os_check = "if os.name == \"nt\":"
        $requests_import = "import requests"

    condition:
        all of ($setup_class, $cmdclass, $install_override, $os_check) and 
        any of ($fernet_decrypt, $exec_decrypted) and 
        $requests_import
}