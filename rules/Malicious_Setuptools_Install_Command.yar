rule Malicious_Setuptools_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools install command overriding with PowerShell file download and execution."
        confidence = 90
        severity = 95
    strings:
        $class_def = "class CustomInstallCommand(install):"
        $download_cmd = "Invoke-WebRequest -Uri "
        $start_process = "Start-Process "
        $powershell = "powershell -Command"
    condition:
        all of them
}