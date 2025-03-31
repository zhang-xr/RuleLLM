rule Suspicious_SetupTools_Install {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setuptools install command overrides"
        confidence = 85
        severity = 80
        
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $custom_install = "class CustomInstall(install)"
        $cmdclass_pattern = "cmdclass={'install':"
        
    condition:
        all of ($setup_import, $install_import) and
        any of ($custom_install, $cmdclass_pattern)
}