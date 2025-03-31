rule MaliciousPythonPackage_SystemInfoCollection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting detailed system information"
        confidence = 80
        severity = 70
    strings:
        $platform_import = "import platform"
        $uptime_read = "with open(\"/proc/uptime\", \"r\")"
        $system_info = "platform.system()"
        $ip_details = "socket.gethostbyname(socket.gethostname())"
    condition:
        3 of them
}