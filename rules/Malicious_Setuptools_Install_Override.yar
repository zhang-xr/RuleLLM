rule Malicious_Setuptools_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages that override setuptools install command to execute custom code"
        confidence = 90
        severity = 80

    strings:
        $setuptools_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $custom_install_class = /class\s+\w+\(\s*install\s*\):/
        $install_override = "cmdclass={'install':"

    condition:
        all of them
}