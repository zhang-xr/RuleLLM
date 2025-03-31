rule Malicious_Pip_Install_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages that override the install class to execute a reverse shell."
        confidence = 90
        severity = 95

    strings:
        $install_class = "class CustomInstall(install):"
        $run_method = "def run(self):"
        $socket_import = "import socket"
        $os_dup2 = "os.dup2"
        $pty_spawn = "pty.spawn"
        $base64_encode = "base64.b64encode"
        $os_system = "os.system"
        $format_lhost = ".format(LHOST="
        $format_lport = "LPORT="

    condition:
        $install_class and $run_method and 
        (3 of ($socket_import, $os_dup2, $pty_spawn, $base64_encode, $os_system)) and
        (1 of ($format_lhost, $format_lport))
}