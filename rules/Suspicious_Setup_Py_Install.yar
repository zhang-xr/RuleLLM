rule Suspicious_Setup_Py_Install {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py with custom install command"
        confidence = 85
        severity = 80
    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $setup_py = "setup("
        $install_requires = "install_requires"
        $startup_path = /AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu/i
    condition:
        all of ($custom_install, $setup_py) and any of ($install_requires, $startup_path)
}