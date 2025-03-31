rule Malicious_Setup_Py {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup.py files with custom install classes and exfiltration behavior"
        confidence = 90
        severity = 85

    strings:
        $setup_call = "setup("
        $cmdclass = /cmdclass\s*=\s*\{.*\}/
        $requests_get = "requests.get"
        $sensitive_imports = /import\s+(requests|getpass|socket|os)/

    condition:
        $setup_call and $cmdclass and $requests_get and $sensitive_imports
}