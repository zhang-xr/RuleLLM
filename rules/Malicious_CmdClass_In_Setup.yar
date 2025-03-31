rule Malicious_CmdClass_In_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects a malicious custom cmdclass in a Python setup script."
        confidence = 85
        severity = 90

    strings:
        $setup_func = "setup("
        $cmdclass = "cmdclass={'install':"
        $custom_install = "class CustomInstall"

    condition:
        all of them and filesize < 10KB
}