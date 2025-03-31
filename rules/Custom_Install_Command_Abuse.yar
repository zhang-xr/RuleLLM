rule Custom_Install_Command_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that override the install command to execute malicious code."
        confidence = 85
        severity = 75
    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $socket_gethostname = "socket.gethostname()"
        $socket_gethostbyname = "socket.gethostbyname("
        $webhook_send = "await webhook.send("
    condition:
        $custom_install and 
        ($socket_gethostname or $socket_gethostbyname) and 
        $webhook_send
}