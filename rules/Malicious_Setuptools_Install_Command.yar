rule Malicious_Setuptools_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious use of setuptools with a custom install command to exfiltrate system information"
        confidence = 90
        severity = 80
    strings:
        $setuptools_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $custom_install_class = "class CustomInstall(install)"
        $cmdclass_setup = "cmdclass={'install': CustomInstall}"
    condition:
        all of them
}