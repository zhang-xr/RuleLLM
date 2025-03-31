rule Python_SystemInfo_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects and sends system information to external servers"
        confidence = 85
        severity = 75
    strings:
        $getuser = "getpass.getuser()"
        $getcwd = "os.getcwd()"
        $gethostname = "socket.gethostname()"
        $requests_post = /requests\.post\(["'].+["']/
    condition:
        all of them
}