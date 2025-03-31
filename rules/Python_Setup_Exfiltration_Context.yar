rule Python_Setup_Exfiltration_Context {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup.py files that exfiltrate data during installation."
        confidence = 90
        severity = 85

    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $requests_import = "import requests"
        $socket_import = "import socket"
        $os_import = "import os"
        $getpass_import = "import getpass"

    condition:
        all of ($setup_import, $install_import, $requests_import, $socket_import, $os_import, $getpass_import)
}