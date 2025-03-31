rule Python_Setup_With_Hidden_PS_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that hide PowerShell execution"
        confidence = "90"
        severity = "85"
    
    strings:
        // Setup script indicators
        $setup1 = "from distutils.core import setup" ascii wide
        $setup2 = "setup(" ascii wide
        
        // Hidden PowerShell execution
        $hidden_ps = "CREATE_NO_WINDOW" ascii wide
        
        // Error suppression
        $try_except = "try:" ascii wide
        $pass = "pass" ascii wide
        
    condition:
        // Match if setup script contains hidden PowerShell execution
        ($setup1 and $setup2) and
        ($hidden_ps or ($try_except and $pass)) and
        filesize < 10KB
}