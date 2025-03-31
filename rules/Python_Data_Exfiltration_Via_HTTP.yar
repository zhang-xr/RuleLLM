rule Python_Data_Exfiltration_Via_HTTP {
    meta:
        author = "RuleLLM"
        description = "Detects Python script that collects system information and sends it via HTTP GET request"
        confidence = 90
        severity = 80
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $socket_import = "import socket"
        $getpass_import = "import getpass"
        $os_import = "import os"
        $requests_import = "import requests"
        $custom_install_class = "class CustomInstall(install)"
        $get_hostname = "socket.gethostname()"
        $get_username = "getpass.getuser()"
        $get_cwd = "os.getcwd()"
        $http_get = "requests.get"
        $params_dict = "params = "
    condition:
        all of ($setup_import, $install_import, $socket_import, $getpass_import, $os_import, $requests_import) and
        3 of ($custom_install_class, $get_hostname, $get_username, $get_cwd) and
        $http_get and $params_dict
}