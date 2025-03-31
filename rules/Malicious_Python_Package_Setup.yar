rule Malicious_Python_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup files that execute encrypted payloads during installation"
        confidence = 95
        severity = 90

    strings:
        $setup_import = "from setuptools import setup, find_packages"
        $install_import = "from setuptools.command.install import install"
        $os_import = "import os"
        $requests_import = "import requests"
        $fernet_import = "from fernet import Fernet"
        $exec_decrypt = /exec\(Fernet\(.*?\)\.decrypt\(.*?\)\)/
        $install_class = /class \w+Install\(install\):/
        $nt_check = /if os\.name == ["']nt["']:/

    condition:
        all of ($setup_import, $install_import, $os_import) and
        2 of ($requests_import, $fernet_import, $exec_decrypt, $install_class, $nt_check)
}