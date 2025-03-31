rule Malicious_Python_Setuptools_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python code overriding setuptools install command with custom behavior"
        confidence = 85
        severity = 80

    strings:
        $setup_tools = "import setuptools"
        $custom_install = "class CustomInstallCommand"
        $cmdclass = "cmdclass={'install': CustomInstallCommand}"

    condition:
        all of them
}