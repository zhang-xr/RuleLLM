rule Python_RemoteConnection_IPPort {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded IP and port combinations in Python code"
        confidence = "95"
        severity = "85"
    
    strings:
        $ip_pattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
        $port_pattern = /\d{1,5}/
        $connect_call = /\.connect\(\(/
        
    condition:
        $ip_pattern and $port_pattern and $connect_call and
        (#ip_pattern == 1) and  // Ensure only one IP address
        (filesize < 100KB)  // Limit to smaller files typical of malicious scripts
}