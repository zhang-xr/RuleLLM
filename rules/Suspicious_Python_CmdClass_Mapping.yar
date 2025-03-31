rule Suspicious_Python_CmdClass_Mapping {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious cmdclass mappings in Python setup.py files"
        confidence = 85
        severity = 70
    
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass"
        $map = /\'install\'\s*:\s*\w+/
    
    condition:
        all of them and 
        $setup and $cmdclass and $map
}