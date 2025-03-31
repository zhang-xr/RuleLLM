rule Suspicious_PIP_Package {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python PIP packages with hardcoded IP addresses"
        confidence = 95
        severity = 85
        
    strings:
        $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii wide
        $port_pattern = /\d{1,5}/ ascii wide
        $setup_py = "setup.py"
        $socket_import = "import socket"
        
    condition:
        $setup_py and $socket_import and
        $ip_pattern and $port_pattern and
        for any i in (1..5) : (uint32(@ip_pattern + i) == uint32(@port_pattern))
}