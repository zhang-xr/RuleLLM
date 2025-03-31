rule Python_Package_Suspicious_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup patterns with custom install commands"
        confidence = 85
        severity = 75
    strings:
        $setup1 = "from setuptools import setup"
        $setup2 = "from setuptools.command.install import install"
        $setup3 = "class CustomInstallCommand(install)"
        $setup4 = "cmdclass={'install':"
    condition:
        all of ($setup1, $setup2, $setup3, $setup4)
}