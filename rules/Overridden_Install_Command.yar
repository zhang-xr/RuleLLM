rule Overridden_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that override the install command in setuptools"
        confidence = 75
        severity = 65
    strings:
        $install_class = "class CustomInstall(install):"
        $cmdclass = "cmdclass={'install': CustomInstall}"
    condition:
        all of ($install_class, $cmdclass)
}