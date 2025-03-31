rule System_Reconnaissance_Data_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects collection of system information including hostname, IP, environment variables, and current working directory"
        confidence = 85
        severity = 80

    strings:
        $hostname = "socket.gethostname"
        $external_ip = "external_ip"
        $os_environ = "os.environ"
        $walk_cwd = "walk_cwd"
        $json_dumps = "json.dumps"
        $subprocess_run = "subprocess.run"

    condition:
        all of ($hostname, $external_ip, $os_environ, $walk_cwd) and 
        any of ($json_dumps, $subprocess_run)
}