rule Python_CustomInstall_Malicious {
    meta:
        author = "RuleLLM"
        description = "Detects malicious custom install commands in setup.py"
        confidence = 95
        severity = 100
        reference = "Malicious pip install command"
    
    strings:
        $custom_install = "class CustomInstall(install)"
        $os_system = "os.system("
        $cmdclass = "cmdclass={'install': CustomInstall}"
    
    condition:
        all of ($custom_install, $os_system, $cmdclass)
}