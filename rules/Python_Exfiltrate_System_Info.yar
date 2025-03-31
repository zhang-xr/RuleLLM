rule Python_Exfiltrate_System_Info {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects and exfiltrates system information"
        confidence = 90
        severity = 80
    strings:
        $socket_gethostname = "socket.gethostname()"
        $os_getcwd = "os.getcwd()"
        $getpass_user = "getpass.getuser()"
        $requests_get = "requests.get"
        $params_dict = /\{\s*['"].+['"]\s*:\s*.+,\s*['"].+['"]\s*:\s*.+,\s*['"].+['"]\s*:\s*.+\s*\}/
    condition:
        all of them and filesize < 10KB
}