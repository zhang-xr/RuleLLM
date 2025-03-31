rule Suspicious_Setup_Py {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py files that may contain malicious code"
        confidence = 80
        severity = 75
    strings:
        $setup_import = "from setuptools import setup"
        $tempfile_import = "from tempfile import NamedTemporaryFile"
        $system_import = "from os import system"
        $executable_import = "from sys import executable"
    condition:
        all of ($setup_import, $tempfile_import, $system_import, $executable_import)
}