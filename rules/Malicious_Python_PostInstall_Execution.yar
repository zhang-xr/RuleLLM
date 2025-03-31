rule Malicious_Python_PostInstall_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious post-install execution in Python setup.py files"
        confidence = 85
        severity = 90
    strings:
        $setup = "from setuptools import setup, find_packages"
        $install = "from setuptools.command.install import install"
        $custom_install = "class [a-zA-Z0-9_]*InstallStrat(install)"
        $main_call = "main()"
    condition:
        $setup and $install and $custom_install and $main_call
}