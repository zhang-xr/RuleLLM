rule Custom_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects custom install commands in Python setuptools, often used for malicious purposes."
        confidence = 95
        severity = 85

    strings:
        $custom_install = "cmdclass={'install':"
        $atexit_register = "atexit.register"

    condition:
        all of them and
        filesize < 10KB
}