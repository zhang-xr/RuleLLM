rule Python_Backdoor_Network_Connection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code establishing network connections during package installation"
        confidence = 90
        severity = 85
        reference = "Hardcoded IP and port in PostInstallCommand"
    
    strings:
        $ip = "123.56.142.180" nocase wide ascii
        $port = "12345" nocase wide ascii
        $socket1 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" nocase wide ascii
        $socket2 = "sock.connect(server_address)" nocase wide ascii
        $install_class = "class PostInstallCommand(install)" nocase wide ascii
    
    condition:
        all of them and 
        filesize < 100KB
}