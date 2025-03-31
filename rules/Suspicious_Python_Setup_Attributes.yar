rule Suspicious_Python_Setup_Attributes {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious attributes in Python setup scripts that may indicate malicious intent"
        confidence = 85
        severity = 80
        
    strings:
        $setup = "from distutils.core import setup"
        $empty_try = "try:" wide ascii
        $empty_except = "except: pass" wide ascii
        $subprocess = "import subprocess" nocase
        $os = "import os" nocase
        $hidden = "Hidden" nocase
        $creationflags = "CREATE_NO_WINDOW"
        
    condition:
        all of ($setup) and
        any of ($empty_try, $empty_except) and
        any of ($subprocess, $os) and
        any of ($hidden, $creationflags)
}