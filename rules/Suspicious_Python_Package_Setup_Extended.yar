rule Suspicious_Python_Package_Setup_Extended {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup configuration"
        confidence = 85
        severity = 75
    strings:
        $cmd_class = "cmdclass={'install': AbortInstall}"
        $suspicious_url = "http://evilpackage.fatezero.org/"
        $suspicious_email = "evilpy@fatezero.org"
    condition:
        all of them
}