rule Python_Setup_With_Stealth_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts with hidden execution patterns"
        confidence = 90
        severity = 85
        
    strings:
        $setup = "from distutils.core import setup"
        $try_except = "try:" wide
        $hidden_exec = "WindowStyle Hidden" nocase
        $github_raw = "github.com" nocase wide
        $exe_file = ".exe" wide
        
    condition:
        all of ($setup, $try_except) and 
        any of ($hidden_exec, $github_raw, $exe_file) and
        filesize < 15KB
}