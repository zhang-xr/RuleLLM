rule Python_Install_Time_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects custom install commands in Python packages"
        confidence = 95
        severity = 85
    strings:
        $install_class = "class CustomInstallCommand" ascii wide
        $cmdclass = "cmdclass={'install':" ascii wide
        $setup_import = "from setuptools import" ascii wide
        $install_import = "from setuptools.command.install import install" ascii wide
    condition:
        $setup_import and $install_import and ($install_class or $cmdclass)
}