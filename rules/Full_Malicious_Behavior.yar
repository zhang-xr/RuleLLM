rule Full_Malicious_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects combination of system info collection, remote socket connection, and post-install hook."
        confidence = 95
        severity = 95
    strings:
        $ip = "134.209.85.64" nocase
        $port = "9090"
        $uptime = "/proc/uptime"
        $platform_release = "platform.release()"
        $post_install = "cmdclass={'install': PostInstallCommand}"
    condition:
        ($ip and $port) and ($uptime or $platform_release) and $post_install
}