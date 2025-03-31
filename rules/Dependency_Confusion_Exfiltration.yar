rule Dependency_Confusion_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects dependency confusion attack with system info exfiltration via DNS"
        confidence = 90
        severity = 85
    strings:
        $s1 = "socket.getaddrinfo(t_str, 80)" 
        $s2 = "getpass.getuser()"
        $s3 = "socket.gethostname()"
        $s4 = "os.getcwd()"
        $s5 = /v2_f\.\d+\.\d+\.\w+\.v2_e\.\w+\.oastify\.com/
        $s6 = "CustomInstall(install)"
    condition:
        all of them
}