rule Malicious_Setuptools_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools installation commands"
        confidence = 90
        severity = 85
        
    strings:
        $install_class = "class CustomInstallCommand(install)"
        $cmdclass_dict = "cmdclass={'install': CustomInstallCommand}"
        $socket_import = /import\s+socket/
        $system_info = /hostname\s*=\s*socket\.gethostname/
        
    condition:
        all of ($install_class, $cmdclass_dict) and any of ($socket_import, $system_info)
}