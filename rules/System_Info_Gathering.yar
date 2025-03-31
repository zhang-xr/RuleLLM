rule System_Info_Gathering {
    meta:
        author = "RuleLLM"
        description = "Detects gathering of system information including hostname and external IP"
        confidence = 85
        severity = 80
    strings:
        $gethostname = "socket.gethostname()"
        $external_ip = "external_ip()"
        $walk_cwd = "walk_cwd()"
        $subprocess = "subprocess.run"
    condition:
        $gethostname and $external_ip and $walk_cwd and $subprocess
}