rule Python_CustomInstall_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts abusing custom install commands to execute malicious code"
        confidence = 90
        severity = 80

    strings:
        $install_class = "class CustomInstallCommand(install)"
        $subprocess_run = "subprocess.run"
        $powershell_cmd = "powershell"
        $start_process = "Start-Process"
        $curl_cmd = "curl.exe"

    condition:
        all of ($install_class, $subprocess_run) and 
        (2 of ($powershell_cmd, $start_process, $curl_cmd))
}