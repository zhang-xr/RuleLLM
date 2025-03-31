rule Malicious_Package_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation behavior using setuptools and Fernet decryption"
        confidence = 90
        severity = 85

    strings:
        $install_override = "class { install.run(self) }"
        $fernet_decrypt = "Fernet("
        $exec_decrypt = "exec(Fernet("
        $os_check = "os.name == \"nt\""
        $requests_import = "import requests"
        $fernet_import = "from fernet import Fernet"

    condition:
        all of ($install_override, $fernet_decrypt, $exec_decrypt, $os_check) and 
        any of ($requests_import, $fernet_import)
}