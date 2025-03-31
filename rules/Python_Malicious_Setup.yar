rule Python_Malicious_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects a combination of malicious behaviors in Python setup files including post-install commands, system info collection, and data exfiltration."
        confidence = "98"
        severity = "90"
    strings:
        $setup = "setup("
        $post_install = "cmdclass={'install'"
        $install_class = "class PostInstallCommand"
        $uptime = "/proc/uptime"
        $platform = "platform."
        $socket = "socket.gethostbyname"
        $socket_connect = "socket.connect"
        $socket_send = "socket.send"
        $ip_address = "134.209.85.64"
    condition:
        3 of ($setup, $post_install, $install_class) and 2 of ($uptime, $platform, $socket) and 2 of ($socket_connect, $socket_send, $ip_address)
}