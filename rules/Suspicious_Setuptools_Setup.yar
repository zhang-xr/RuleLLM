rule Suspicious_Setuptools_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setuptools setup with custom install commands."
        confidence = 80
        severity = 85
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass={"
        $install = "'install':"
    condition:
        all of them
}