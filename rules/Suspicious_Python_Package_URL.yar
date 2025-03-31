rule Suspicious_Python_Package_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL in Python package setup"
        confidence = 85
        severity = 70
        
    strings:
        $s1 = "http://evilpackage.fatezero.org/"
        $s2 = "url = \"http://evilpackage.fatezero.org/\""
        
    condition:
        any of them
}