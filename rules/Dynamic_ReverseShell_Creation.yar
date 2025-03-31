rule Dynamic_ReverseShell_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic reverse shell creation in Python scripts"
        confidence = 88
        severity = 92

    strings:
        $socket_import = "import socket"
        $pty_import = "import pty"
        $reverse_shell = /s\.connect\(\([\'\"].*[\'\"],\s*\d+\)\)/
        $dup2_call = /os\.dup2\(s\.fileno\(\), \d+\)/

    condition:
        all of them
}