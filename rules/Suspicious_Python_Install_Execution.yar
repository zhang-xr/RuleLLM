rule Suspicious_Python_Install_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with suspicious imports and execution patterns"
        confidence = 90
        severity = 80

    strings:
        $import_requests = "import requests"
        $import_fernet = "from fernet import Fernet"
        $exec_decrypt = /exec\(Fernet\(b'[A-Za-z0-9+\/]+={0,2}'\)\.decrypt\(b'[A-Za-z0-9+\/]+={0,2}'\)\)/
        $os_name_check = "if os.name == \"nt\":"

    condition:
        all of them
}