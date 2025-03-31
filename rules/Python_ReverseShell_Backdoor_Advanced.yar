rule Python_ReverseShell_Backdoor_Advanced {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell backdoor using socket and subprocess with advanced indicators"
        confidence = 90
        severity = 95
        reference = "Analysis of malicious Python package"
    
    strings:
        $socket_import = "import socket" ascii wide
        $subprocess_import = "import subprocess" ascii wide
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" ascii wide
        $socket_connect = "sock.connect((" ascii wide
        $cmd_exec = /subprocess\.(Popen|call)\(\[[\"'](cmd|bash)[\"']/ ascii wide
        $dup2 = "os.dup2(sock.fileno()" ascii wide
        $install_hook = "cmdclass={'install':" ascii wide
    
    condition:
        all of ($socket_import, $subprocess_import) and 
        3 of ($socket_create, $socket_connect, $cmd_exec, $dup2, $install_hook)
}