rule Python_SystemInfoCollection {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious system information collection in Python code"
        confidence = 85
        severity = 80
    strings:
        $platform_import = "import platform"
        $socket_import = "import socket"
        $gethostname = "socket.gethostname()"
        $platform_methods = /platform\.(system|release|version|platform)/
        $uptime_check = "/proc/uptime"
    condition:
        3 of them and filesize < 15KB
}