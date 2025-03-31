rule Python_ReverseShell_Network {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell network connection patterns"
        confidence = 90
        severity = 85
    
    strings:
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $socket_connect = "s.connect"
        $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $port_pattern = /\d{4,5}/
        
    condition:
        $socket_create and $socket_connect and
        $ip_pattern and $port_pattern and
        #ip_pattern < 100 and #port_pattern < 100
}