rule Python_Dependency_Confusion_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that exfiltrate system information during installation"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstall(install):"
        $requests_import = "import requests"
        $socket_import = "import socket"
        $getpass_import = "import getpass"
        $os_import = "import os"
        $http_request = /requests\.get\s*\(\s*["'][^"']+["']/
    condition:
        all of ($install_class, $requests_import, $socket_import, $getpass_import, $os_import) and $http_request
}