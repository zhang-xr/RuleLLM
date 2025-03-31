rule Base64_ReverseShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded reverse shell execution in Python scripts."
        confidence = 85
        severity = 90

    strings:
        $base64_encode = "base64.b64encode"
        $base64_decode = "base64 -d"
        $bash_exec = "|bash"
        $os_system = "os.system"
        $socket_connect = "s.connect"
        $os_dup2 = "os.dup2"
        $pty_spawn = "pty.spawn"

    condition:
        ($base64_encode and $base64_decode and $bash_exec) and
        (2 of ($socket_connect, $os_dup2, $pty_spawn)) and
        $os_system
}