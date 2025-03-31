rule Malicious_InfoStealer_HTTP_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based information stealer that collects system info and exfiltrates via HTTP POST"
        confidence = 90
        severity = 80

    strings:
        $package_name = "PACKAGE_NAME" ascii wide
        $hostname = "HOSTNAME" ascii wide
        $current_path = "CURRENT_PATH" ascii wide
        $data_dict = "data = {" ascii wide
        $requests_post = "requests.post(" ascii wide
        $socket_gethostname = "socket.gethostname()" ascii wide
        $os_getcwd = "os.getcwd()" ascii wide

    condition:
        all of them and
        filesize < 10KB
}