rule Python_DependencyConfusion_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python dependency confusion attacks with data exfiltration"
        confidence = 90
        severity = 80
    strings:
        $install_hook = "cmdclass={'install':"
        $requests_import = "import requests"
        $getpass_import = "import getpass"
        $socket_import = "import socket"
        $get_request = /requests\.get\s*\([\s\S]{1,200}oastify\.com/
    condition:
        all of them and
        filesize < 10KB
}