rule Data_Exfiltration_SystemInfo_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information and sends it to an external URL"
        confidence = 80
        severity = 70
        
    strings:
        $platform_system = "platform.system()"
        $psutil_boot_time = "psutil.boot_time()"
        $socket_gethostname = "socket.gethostname()"
        $requests_post = /requests\.post\(["'].+?["']/
        $webhook_url = "https://webhook.site/baf67bd8-bf43-41ae-8af2-4a0fb906f90d/analytics"
        
    condition:
        all of ($platform_system, $psutil_boot_time, $socket_gethostname) and 
        ($requests_post or $webhook_url)
}