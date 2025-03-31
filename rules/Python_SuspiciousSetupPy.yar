rule Python_SuspiciousSetupPy {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious patterns in Python setup.py files"
        confidence = 85
        severity = 80
    strings:
        $setup_function = "setup("
        $install_requires = "install_requires"
        $requests = "requests"
        $cmdclass = "cmdclass"
        $base64_encode = "base64.b64encode"
    condition:
        3 of them and
        filesize < 10KB
}