rule Malicious_Python_Setup_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that override install command for malicious purposes"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstallCommand(install):"
        $setup_override = "cmdclass={'install': CustomInstallCommand,"
        $powershell = "powershell -Command"
        $invoke_webrequest = "Invoke-WebRequest"
        $start_process = "Start-Process"
    condition:
        all of ($install_class, $setup_override) and 
        any of ($powershell, $invoke_webrequest, $start_process)
}