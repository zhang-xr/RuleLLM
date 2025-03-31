rule Python_MaliciousPackage_DownloadExec {
    meta:
        author = "RuleLLM"
        description = "Detects Python malicious packages that download and execute external executables during installation"
        confidence = 95
        severity = 90
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $subprocess_import = "import subprocess"
        $powershell_download = "Invoke-WebRequest -Uri"
        $powershell_execute = "Start-Process"
        $custom_install_class = "class CustomInstallCommand(install)"
    condition:
        all of them and 
        filesize < 10KB
}