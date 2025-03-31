rule Python_System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that collect sensitive system information (username, CWD, hostname)."
        confidence = 70
        severity = 60
    strings:
        $getpass = "getpass.getuser()"
        $os_cwd = "os.getcwd()"
        $socket_hostname = "socket.gethostname()"
    condition:
        all of ($getpass, $os_cwd, $socket_hostname)
}