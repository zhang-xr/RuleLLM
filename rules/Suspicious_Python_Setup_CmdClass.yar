rule Suspicious_Python_Setup_CmdClass {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of cmdclass in Python setup.py scripts"
        confidence = 80
        severity = 85

    strings:
        $cmdclass = "cmdclass={'install':"
        $custom_install = "class CustomInstall(install)"

    condition:
        all of them
}