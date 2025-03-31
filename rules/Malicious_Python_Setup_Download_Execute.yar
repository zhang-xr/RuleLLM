rule Malicious_Python_Setup_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that download and execute external files during installation"
        confidence = 90
        severity = 80

    strings:
        $setup_import = "from setuptools import setup"
        $custom_install = "class CustomInstallCommand(install)"
        $subprocess_import = "import subprocess"
        $os_import = "import os"
        $powershell_exec = "subprocess.run([\"powershell\", \"-Command\""
        $start_process = "Start-Process"
        $curl_download = "curl.exe -L"
        $discord_cdn_url = /https:\/\/cdn\.discordapp\.com\/attachments\/\d+\/\d+\/[^\s]+/

    condition:
        all of ($setup_import, $custom_install, $subprocess_import, $os_import) and
        any of ($powershell_exec, $start_process) and
        any of ($curl_download, $discord_cdn_url)
}