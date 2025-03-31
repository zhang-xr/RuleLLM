rule Python_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with data exfiltration patterns"
        confidence = "85"
        severity = "80"
    
    strings:
        $requests = "requests.get("
        $env1 = "os.getenv('USER')"
        $env2 = "os.getenv('HOSTNAME')"
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
    
    condition:
        $requests and 
        (2 of ($env1, $env2, $hostname, $cwd))
}