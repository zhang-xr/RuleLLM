rule Python_Install_Hook_Advanced {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools install command override with advanced indicators"
        confidence = 95
        severity = 90
        reference = "Analysis of malicious Python package"
    
    strings:
        $install_class = "class execute(install)" ascii wide
        $cmdclass = "cmdclass={'install': execute}" ascii wide
    
    condition:
        all of ($install_class, $cmdclass)
}