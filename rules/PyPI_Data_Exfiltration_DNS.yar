rule PyPI_Data_Exfiltration_DNS {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system info and exfiltrates via DNS"
        confidence = 95
        severity = 90
    strings:
        $data_collection = /(socket\.gethostname\(\)|getpass\.getuser\(\)|os\.getcwd\(\))/
        $json_convert = "json.dumps(data)"
        $hex_encode = ".encode('utf-8').hex()"
        $dns_lookup = "socket.getaddrinfo("
        $oastify_domain = /\.oastify\.com/
    condition:
        3 of them and $oastify_domain
}