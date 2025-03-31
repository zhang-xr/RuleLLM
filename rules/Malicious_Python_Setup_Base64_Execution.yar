rule Malicious_Python_Setup_Base64_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup files with base64-encoded malicious code in custom install commands"
        confidence = 90
        severity = 90
    strings:
        $setup_import = "from setuptools import setup, find_packages"
        $custom_install = "class CustomInstallCommand(install):"
        $base64_exec = /exec\(base64\.b64decode\([\"'][a-zA-Z0-9+\/]+={0,2}[\"']\)\)/
    condition:
        all of them
}