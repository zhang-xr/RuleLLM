rule Python_Package_System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that collect system information (hostname, OS, IP) for exfiltration."
        confidence = "85"
        severity = "75"
    strings:
        $platform_node = "platform.node()" ascii wide
        $platform_system = "platform.system()" ascii wide
        $ipify_url = "https://api.ipify.org" ascii wide
        $requests_get = "requests.get(" ascii wide
    condition:
        all of them
}