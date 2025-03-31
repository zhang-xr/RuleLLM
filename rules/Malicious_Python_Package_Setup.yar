rule Malicious_Python_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup patterns"
        confidence = 95
        severity = 85
        
    strings:
        $s1 = "class AbortInstall(install):"
        $s2 = "raise SystemExit"
        $s3 = "http://evilpackage.fatezero.org/"
        $s4 = "cmdclass = {'install': AbortInstall}"
        $s5 = "setuptools.setup"
        $s6 = "name=\"usar_agent\""
        
    condition:
        4 of them
}