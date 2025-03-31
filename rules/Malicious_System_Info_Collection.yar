rule Malicious_System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects system information collection including MAC addresses, hostname, username, and current directory"
        confidence = 90
        severity = 80
        
    strings:
        $get_mac_addresses = "get_mac_addresses"
        $platform_node = "platform.node()"
        $getpass_getuser = "getpass.getuser()"
        $os_getcwd = "os.getcwd()"
        $subprocess_check_output = "subprocess.check_output"
        
    condition:
        all of them
}