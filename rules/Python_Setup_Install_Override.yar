rule Python_Setup_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts overriding install command for potential malicious behavior"
        confidence = 85
        severity = 70
    
    strings:
        $class_def = "class create(install):"
        $setup_call = "setup("
        $cmdclass = "'cmdclass'"
        $install_override = /['"]install['"]\s*:\s*\w+/
    
    condition:
        all of them and 
        filesize < 10KB
}