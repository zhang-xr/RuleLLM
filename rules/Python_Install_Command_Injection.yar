rule Python_Install_Command_Injection {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation commands that override install class"
        confidence = 85
        severity = 75
    strings:
        $cmdclass = "cmdclass={'install': CustomInstall}"
        $install_class = "class CustomInstall(install):"
    condition:
        $cmdclass and
        $install_class in (@install_class..@install_class + 200)
}