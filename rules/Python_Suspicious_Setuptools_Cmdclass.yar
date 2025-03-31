rule Python_Suspicious_Setuptools_Cmdclass {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of cmdclass in setuptools setup"
        confidence = 80
        severity = 85

    strings:
        $cmdclass = "cmdclass={'install':"
        $setup = "setup("

    condition:
        all of them
}