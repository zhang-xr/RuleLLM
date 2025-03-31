rule Suspicious_Python_Setup_System_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that exfiltrate system information (hostname and IP) using Discord webhooks."
        confidence = 85
        severity = 75
    strings:
        $gethostname = "socket.gethostname"
        $gethostbyname = "socket.gethostbyname"
        $webhook = "Webhook.from_url"
        $install_requires = "install_requires"
    condition:
        all of ($gethostname, $gethostbyname, $webhook) and $install_requires
}