rule Malicious_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code exfiltrating system information to a remote server"
        confidence = 90
        severity = 80
    strings:
        $socket_gethostname = "socket.gethostname()"
        $os_getcwd = "os.getcwd()"
        $requests_post = "requests.post"
        $data_dict = /data\s*=\s*{.*}/
        $url_var = /\w+\s*=\s*"https?:\/\/[^"]+"/
    condition:
        all of them and 
        $requests_post and 
        ($socket_gethostname or $os_getcwd) and 
        $data_dict and 
        $url_var
}