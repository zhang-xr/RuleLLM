rule System_Info_Collection_Combined {
    meta:
        author = "RuleLLM"
        description = "Detects collection of system information including uptime, OS details, and network interfaces."
        confidence = 80
        severity = 75
    strings:
        $uptime = "/proc/uptime"
        $platform_release = "platform.release()"
        $platform_system = "platform.system()"
        $platform_version = "platform.version()"
        $psutil_net = "psutil.net_if_addrs()"
    condition:
        3 of ($uptime, $platform_release, $platform_system, $platform_version, $psutil_net)
}