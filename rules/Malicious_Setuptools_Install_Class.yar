rule Malicious_Setuptools_Install_Class {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages using setuptools with a custom install class for exfiltration"
        confidence = 90
        severity = 80

    strings:
        $setuptools_import = "from setuptools import setup"
        $install_class = /class\s+\w+\(install\):/
        $requests_import = "import requests"
        $getpass_import = "import getpass"
        $socket_import = "import socket"
        $os_import = "import os"

    condition:
        all of ($setuptools_import, $install_class) and 
        3 of ($requests_import, $getpass_import, $socket_import, $os_import)
}