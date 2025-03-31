rule Python_DependencyConfusion_DNS_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python dependency confusion attack with DNS exfiltration pattern"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class CustomInstall(install)"
        $socket_getaddrinfo = "socket.getaddrinfo(t_str, 80)"
        $data_collection = /['"]\w['"]\s*:\s*\[(socket\.gethostname\(\)|getpass\.getuser\(\)|os\.getcwd\(\))\]/
        $hex_encode = ".encode('utf-8').hex()"
        $chunking = "chunks = len(hex_str) //"
    condition:
        all of them
}