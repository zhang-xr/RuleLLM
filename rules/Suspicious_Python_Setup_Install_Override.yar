rule Suspicious_Python_Setup_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts overriding the install command for malicious purposes"
        confidence = 85
        severity = 75

    strings:
        $install_override = "class CustomInstallCommand(install):"
        $cmdclass = "cmdclass={'install': CustomInstallCommand}"
        $socket_import = "import socket"
        $webhook_import = /import\s+(discord|SyncWebhook)/ nocase

    condition:
        all of ($install_override, $cmdclass) and
        any of ($socket_import, $webhook_import)
}