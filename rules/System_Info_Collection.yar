rule System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information such as uptime, OS details, and IP address."
        confidence = "90"
        severity = "70"
    strings:
        $uptime = "/proc/uptime"
        $platform = "platform."
        $socket = "socket.gethostbyname"
    condition:
        all of them
}