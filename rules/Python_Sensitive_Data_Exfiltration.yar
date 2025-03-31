rule Python_Sensitive_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that collect and exfiltrate sensitive system information."
        confidence = 80
        severity = 70
    strings:
        $getpass = "getpass.getuser()"
        $os_cwd = "os.getcwd()"
        $socket_hostname = "socket.gethostname()"
        $requests_post = "requests.post"
        $http_url = /https?:\/\/[^\s"]+/
    condition:
        all of ($getpass, $os_cwd, $socket_hostname, $requests_post) and $http_url
}