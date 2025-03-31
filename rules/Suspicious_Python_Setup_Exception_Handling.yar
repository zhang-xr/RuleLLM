rule Suspicious_Python_Setup_Exception_Handling {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup scripts with generic exception handling"
        confidence = 85
        severity = 80
    
    strings:
        $setup_import = "from distutils.core import setup"
        $try_except = "try:" wide ascii
        $pass_stmt = "pass" wide ascii
        $subprocess = "import subprocess" wide ascii
        $os_import = "import os" wide ascii
        
    condition:
        all of them and 
        #try_except >= 2 and 
        #pass_stmt >= 2 and 
        filesize < 10KB
}