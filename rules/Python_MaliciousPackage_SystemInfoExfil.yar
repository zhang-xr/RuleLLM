rule Python_MaliciousPackage_SystemInfoExfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that collect and exfiltrate system information"
        confidence = "90"
        severity = "80"
    
    strings:
        $socket_import = "import socket"
        $platform_import = "import platform"
        $gethostname = "socket.gethostname()"
        $gethostbyname = "socket.gethostbyname"
        $socket_connect = "socket.connect"
        $socket_send = "socket.send"
        $post_install = "PostInstallCommand"
        $cmdclass = "cmdclass"
        
    condition:
        all of ($socket_import, $platform_import) and
        3 of ($gethostname, $gethostbyname, $socket_connect, $socket_send) and
        all of ($post_install, $cmdclass)
}