rule Python_ReverseShell_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with reverse shell installation"
        confidence = 90
        severity = 95
        reference = "Custom pip install command with reverse shell"
    
    strings:
        $socket_connect = /s\.connect\(\([\'\"].+[\'\"],\s*\d+\)\)/
        $os_dup2 = "os.dup2(s.fileno()"
        $pty_spawn = "pty.spawn("
        $base64_exec = /os\.system\([\'\"].*base64.*\|bash/
        $custom_install = "class CustomInstall(install)"
    
    condition:
        all of ($socket_connect, $os_dup2, $pty_spawn) and 
        (1 of ($base64_exec, $custom_install))
}