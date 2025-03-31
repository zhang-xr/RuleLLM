rule Python_MaliciousPackage_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with malicious installation behavior that exfiltrates system information"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstall(install)"
        $setup_import = "from setuptools import setup"
        $requests_import = "import requests"
        $getpass_import = "import getpass"
        $socket_import = "import socket"
        $os_import = "import os"
        $exfil_pattern = /requests\.get\s*\(\s*[\'\"].+\.oastify\.com/
    condition:
        all of ($install_class, $setup_import) and 
        3 of ($requests_import, $getpass_import, $socket_import, $os_import) and
        $exfil_pattern
}