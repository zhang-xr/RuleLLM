rule System_Info_Collection_Python {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system information"
        confidence = 85
        severity = 80

    strings:
        $os_uname = "os.uname()"
        $os_getcwd = "os.getcwd()"
        $socket_gethostname = "socket.gethostname()"
        $os_getlogin = "os.getlogin()"

    condition:
        3 of ($os_uname, $os_getcwd, $socket_gethostname, $os_getlogin)
}