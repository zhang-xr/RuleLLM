rule Setuptools_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects malicious overrides of setuptools install commands"
        confidence = 95
        severity = 90
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $custom_install = /class\s+\w+\(\s*install\s*\):/
    condition:
        all of them and
        filesize < 10KB
}