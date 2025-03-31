rule Python_System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that collect system information"
        confidence = 85
        severity = 70

    strings:
        $os_uname = "os.uname()"
        $os_getcwd = "os.getcwd()"
        $socket_gethostname = "socket.gethostname()"

    condition:
        all of ($os_uname, $os_getcwd, $socket_gethostname)
}