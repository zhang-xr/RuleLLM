rule Malicious_Python_Package_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with reverse shell installation attempts"
        confidence = 95
        severity = 90
    strings:
        $custom_install = "class CustomInstall(install)"
        $reverse_shell = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $base64_decode = "base64.b64encode" nocase
        $os_system = "os.system" nocase
        $os_dup2 = "os.dup2" nocase
        $pty_spawn = "pty.spawn" nocase
    condition:
        all of ($custom_install, $reverse_shell) and 
        any of ($base64_decode, $os_system, $os_dup2, $pty_spawn)
}