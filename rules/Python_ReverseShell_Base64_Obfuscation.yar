rule Python_ReverseShell_Base64_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell implementation with Base64 obfuscation"
        confidence = 90
        severity = 95

    strings:
        $socket = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $dup2 = "os.dup2"
        $subprocess = "subprocess.call"
        $base64_decode = "base64.b64decode"
        $connect = ".connect"
        $shell = "/bin/sh"

    condition:
        all of ($socket, $dup2, $subprocess) and
        any of ($base64_decode, $connect, $shell)
}