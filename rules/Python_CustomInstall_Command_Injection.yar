rule Python_CustomInstall_Command_Injection {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious custom install commands in Python setup scripts"
        confidence = 85
        severity = 75
    strings:
        $custom_install = "class CustomInstallCommand(install)" nocase
        $os_system = "os.system(" nocase
        $pre_install = "pre_install" nocase
    condition:
        all of them
}