rule Malicious_Python_Package_DNS_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that exfiltrate data through DNS queries during installation"
        confidence = 90
        severity = 80
    strings:
        $dns_exfil1 = /dns_request\([^)]+\)/
        $cmd_hook1 = "class CustomInstallCommand(install)"
        $cmd_hook2 = "class CustomDevelopCommand(develop)"
        $cmd_hook3 = "class CustomEggInfoCommand(egg_info)"
        $data_collect1 = "socket.gethostname()"
        $data_collect2 = "getpass.getuser()"
        $data_collect3 = "os.getcwd()"
        $hex_encode = ".encode('utf-8').hex()"
        $chunk_split = /\[hex_str\[\(i \* \d+\):\(i \+ 1\) \* \d+\] for i in range\(0, chunks \+ 1\)\]/
    condition:
        (3 of ($cmd_hook*)) and 
        (2 of ($data_collect*)) and 
        ($dns_exfil1 or $hex_encode or $chunk_split)
}