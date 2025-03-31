rule Malicious_Python_Package_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with custom install classes that execute malicious commands."
        confidence = 90
        severity = 95
    strings:
        $custom_install = "class CustomInstall(install)"
        $install_run = "def run(self):"
        $os_system = "os.system"
        $base64_encode = "base64.b64encode"
        $reverse_shell = /s\.connect\(\([\'\"].*[\'\"]\,\s*\d+\)\)/
    condition:
        all of ($custom_install, $install_run, $os_system) and 
        any of ($base64_encode, $reverse_shell)
}