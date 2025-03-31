rule Malicious_Python_Setup_FileCreation {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup.py files that create files during installation"
        confidence = 90
        severity = 80
    
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass"
        $file_write = /with open\s*\([\s\S]*\/tmp\/[^\)]+\) as \w+/
    
    condition:
        all of them
}