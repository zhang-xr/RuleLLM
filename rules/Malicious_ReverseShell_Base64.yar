rule Malicious_ReverseShell_Base64 {
    meta:
        author = "RuleLLM"
        description = "Detects reverse shell creation with base64 obfuscation in Python code"
        confidence = 90
        severity = 95

    strings:
        $socket_import = "import socket"
        $base64_import = "import base64"
        $base64_decode = "base64.b64decode"
        $socket_connect = "s.connect"
        $dup2_call = "os.dup2"
        $subprocess_call = "subprocess.call"
        $reverse_shell_pattern = /s\.connect\(\(.*,\s*int\(.*\)\)\)/

    condition:
        all of ($socket_import, $base64_import, $base64_decode, $socket_connect, $dup2_call, $subprocess_call) and
        $reverse_shell_pattern
}