rule Malicious_Python_Custom_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with custom install commands for malicious behavior"
        confidence = 95
        severity = 90

    strings:
        $custom_install = "class CustomInstallCommand(install):" nocase
        $os_env = "os.environ[" nocase
        $os_getlogin = "os.getlogin(" nocase
        $setup_cmdclass = "cmdclass={" nocase

    condition:
        all of them and
        filesize < 10KB
}