rule Python_Combined_Malicious_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects combined malicious behavior including reverse shell, suspicious URL fetching, and malicious package installation."
        confidence = 95
        severity = 100

    strings:
        $socket_create = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $socket_connect = /s\.connect\(\("[\d\.]+",\s*\d+\)\)/
        $dup2 = "os.dup2(s.fileno(),"
        $spawn_shell = "pty.spawn(\"/bin/sh\")"
        $post_install_class = "class PostInstallCommand(install):"
        $run_method = "def run(self):"
        $urlopen = "urllib.request.urlopen("
        $suspicious_url = /https?:\/\/[^\s\/]+\.[^\s\/]+\/[^\s\)]+/

    condition:
        3 of ($socket_create, $socket_connect, $dup2, $spawn_shell) and
        2 of ($post_install_class, $run_method) and
        ($urlopen and $suspicious_url)
}