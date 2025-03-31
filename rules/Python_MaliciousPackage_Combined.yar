rule Python_MaliciousPackage_Combined {
    meta:
        author = "RuleLLM"
        description = "Comprehensive detection of malicious Python package patterns"
        confidence = 98
        severity = 95
    strings:
        $network_patterns1 = "socket.connect"
        $network_patterns2 = "socket.socket"
        $network_patterns3 = "send("
        $install_patterns1 = "PostInstallCommand"
        $install_patterns2 = "setuptools.command.install"
        $install_patterns3 = "cmdclass"
        $info_patterns1 = "import platform"
        $info_patterns2 = "import socket"
        $info_patterns3 = "/proc/uptime"
    condition:
        (2 of ($network_patterns*)) and 
        (2 of ($install_patterns*)) and 
        (2 of ($info_patterns*)) and 
        filesize < 20KB
}