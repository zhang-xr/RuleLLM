rule Python_SystemInfo_Exfiltration_Combined {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts collecting system information and sending it via HTTP POST"
        confidence = 80
        severity = 70
    strings:
        $getuser = "getpass.getuser()"
        $getcwd = "os.getcwd()"
        $gethostname = "socket.gethostname()"
        $post_request = /requests\.post\(.*?\{.*?\}.*?\)/
    condition:
        all of ($getuser, $getcwd, $gethostname) and $post_request
}