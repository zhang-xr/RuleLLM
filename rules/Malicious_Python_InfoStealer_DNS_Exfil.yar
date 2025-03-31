rule Malicious_Python_InfoStealer_DNS_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based information stealer using DNS exfiltration"
        confidence = 90
        severity = 85
    strings:
        $dns_exfil1 = /socket\.gethostbyname\([^\)]+\.ns\.depcon\.buzz/
        $b32encode = "b32encode"
        $data_collect1 = "socket.gethostname()"
        $data_collect2 = "os.environ.items()"
        $data_collect3 = "external_ip()"
        $compress = "compress"
    condition:
        3 of them and filesize < 10KB
}