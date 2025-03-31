rule Python_ReverseShell_Context {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell with context-aware patterns"
        confidence = 95
        severity = 100

    strings:
        $dup2 = "os.dup2"
        $subprocess_call = "subprocess.call"
        $socket_create = "socket.socket"
        $socket_connect = "s.connect"
        $reverse_shell = "/bin/sh" nocase
        $base64_decode = "base64.b64decode"

    condition:
        all of ($dup2, $subprocess_call, $socket_create, $socket_connect) and
        any of ($reverse_shell, $base64_decode)
}