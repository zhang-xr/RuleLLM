rule PowerShell_Download_And_Execute_In_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to download and execute files in a Python setup script."
        confidence = 90
        severity = 80

    strings:
        $powershell_download = "Invoke-WebRequest" nocase
        $powershell_execute = "Start-Process" nocase
        $subprocess_run = "subprocess.run"
        $setup_import = "from setuptools import setup"
        $custom_install = "class CustomInstallCommand"

    condition:
        all of ($setup_import, $custom_install, $subprocess_run) and
        (1 of ($powershell_download, $powershell_execute))
}