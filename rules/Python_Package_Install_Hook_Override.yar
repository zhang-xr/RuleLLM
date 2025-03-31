rule Python_Package_Install_Hook_Override {
    meta:
        author = "RuleLLM"
        description = "Detects override of setuptools install/develop commands"
        confidence = "90"
        severity = "80"
    
    strings:
        $cmdclass1 = "cmdclass={"
        $cmdclass2 = "'install':"
        $cmdclass3 = "'develop':"
        $setuptools = "setuptools.setup"
        $class_def = "class After"
    
    condition:
        all of ($cmdclass*) and 
        $setuptools and 
        $class_def and 
        filesize < 10KB
}