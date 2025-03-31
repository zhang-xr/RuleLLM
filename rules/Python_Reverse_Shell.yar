rule Python_Reverse_Shell {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell patterns."
        confidence = 85
        severity = 90
    strings:
        $socket_import = "import socket"
        $pty_import = "import pty"
        $dup2 = "os.dup2"
        $connect = /s\.connect\(\([\'\"].*[\'\"]\,\s*\d+\)\)/
        $spawn = "pty.spawn"
    condition:
        all of ($socket_import, $pty_import, $dup2, $connect, $spawn)
}