rule Python_SuspiciousSetupStructure {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py structure with empty definitions"
        confidence = 80
        severity = 75
        reference = "Setup file with suspicious structure and empty definitions"
    
    strings:
        $setup_import = "from setuptools import"
        $empty_class = /class [A-Za-z0-9_]+:\s*pass/
        $empty_def = /def [A-Za-z0-9_]+\(.*\):\s*pass/
        $cmdclass = "cmdclass={'install':"
        
    condition:
        all of ($setup_import, $cmdclass) and 
        any of ($empty_class, $empty_def) and
        filesize < 50KB
}