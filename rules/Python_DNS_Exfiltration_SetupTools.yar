rule Python_DNS_Exfiltration_SetupTools {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages using setuptools to exfiltrate data via DNS"
        confidence = "90"
        severity = "80"
    
    strings:
        $setup_tools = "from setuptools import setup"
        $custom_cmd = /class Custom(Install|Develop|EggInfo)Command/
        $dns_func = /def dns_request\(.*socket\.AF_INET.*socket\.SOCK_DGRAM/
        $data_collect = /(socket\.gethostname\(\)|getpass\.getuser\(\)|os\.getcwd\(\))/
        $hex_encode = /\.encode\('utf-8'\)\.hex\(\)/
        $dns_send = /s\.sendto\(.*\('[\w\.]+', 53\)\)/
    
    condition:
        all of ($setup_tools, $custom_cmd) and 
        3 of ($dns_func, $data_collect, $hex_encode, $dns_send)
}