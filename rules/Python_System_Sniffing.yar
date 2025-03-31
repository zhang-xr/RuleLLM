rule Python_System_Sniffing {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects multiple system information points"
        confidence = 90
        severity = 80
    strings:
        $getuser = "getpass.getuser()"
        $getcwd = "os.getcwd()"
        $gethostname = "socket.gethostname()"
    condition:
        2 of them
}