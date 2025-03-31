rule System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects code patterns that collect system information such as hostname, IP, and environment variables"
        confidence = 85
        severity = 75

    strings:
        $hostname = "hostname = socket.gethostname()"
        $external_ip = "external_ip()"
        $env_vars = "for k, v in os.environ.items()"
        $proc_status = "/proc/[0-9]+/status"
        $proc_cwd = "/proc/[0-9]+/cwd"

    condition:
        3 of them
}