rule Python_SuspiciousCmdClass {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious cmdclass configuration in Python setup files"
        confidence = 85
        severity = 80
        reference = "Custom installation class with potential malicious override"
    
    strings:
        $cmdclass = "cmdclass={'install':"
        $custom_class = /class [A-Za-z0-9_]+\([A-Za-z0-9_]*\):/
        $empty_def = /def [A-Za-z0-9_]+\(.*\):\s*pass/
        $empty_class = /class [A-Za-z0-9_]+:\s*pass/
        
    condition:
        all of ($cmdclass, $custom_class) and 
        any of ($empty_def, $empty_class) and
        filesize < 50KB
}