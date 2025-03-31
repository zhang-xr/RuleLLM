rule Suspicious_Python_Setup_Class {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup scripts using custom classes during installation"
        confidence = "80"
        severity = "70"
        
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass"
        $custom_class = "class create():"
        $install = "'install'"
        
    condition:
        all of them
}