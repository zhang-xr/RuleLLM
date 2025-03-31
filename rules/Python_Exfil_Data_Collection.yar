rule Python_Exfil_Data_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system information and exfiltrates it via HTTP"
        confidence = "95"
        severity = "90"
    strings:
        $ip_collection = /socket\.socket\(socket\.AF_INET,\s*socket\.SOCK_DGRAM\).*connect\(.*'8\.8\.8\.8',\s*53\).*getsockname\(\)/ nocase
        $data_collection = /os\.getlogin\(\)|platform\.node\(\)|platform\.uname\(\)|os\.getcwd\(\)/ nocase
        $base64_encode = "base64.b64encode" nocase
        $http_exfil = /requests\.get\(.*http:\/\/.*%/ nocase
    condition:
        all of them
}