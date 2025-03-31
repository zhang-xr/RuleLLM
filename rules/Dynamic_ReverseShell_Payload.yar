rule Dynamic_ReverseShell_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic reverse shell payload construction using LHOST and LPORT."
        confidence = 80
        severity = 85

    strings:
        $format_lhost = ".format(LHOST="
        $format_lport = "LPORT="
        $socket_import = "import socket"
        $os_dup2 = "os.dup2"
        $pty_spawn = "pty.spawn"

    condition:
        ($format_lhost and $format_lport) and
        (2 of ($socket_import, $os_dup2, $pty_spawn))
}