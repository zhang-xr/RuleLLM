rule Python_DataExfiltration_CustomInstallCommand {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with custom install commands for data exfiltration"
        confidence = 95
        severity = 90
    strings:
        $install_class = "class CustomInstallCommand(install)"
        $requests_get = "requests.get"
        $base64_encode = "base64.b64encode"
        $setup_function = "setup("
        $cmdclass = "cmdclass"
    condition:
        all of them and
        filesize < 10KB
}