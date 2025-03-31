rule Malicious_Python_Package_AbortInstall {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup that aborts installation and redirects to suspicious website"
        confidence = 90
        severity = 80
        
    strings:
        $s1 = "class AbortInstall(install):"
        $s2 = "raise SystemExit"
        $s3 = "http://evilpackage.fatezero.org/"
        $s4 = "cmdclass = {'install': AbortInstall}"
        
    condition:
        all of them
}