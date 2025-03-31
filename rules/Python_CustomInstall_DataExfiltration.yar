rule Python_CustomInstall_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects custom Python install classes that collect and exfiltrate system information"
        confidence = 90
        severity = 80

    strings:
        // Detect the custom install class definition
        $install_class = /class\s+\w+\s*\(\s*install\s*\):/
        // Detect system information collection
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
        $username = "getpass.getuser()"
        // Detect HTTP request to exfiltrate data
        $http_request = /requests\.get\s*\(/

    condition:
        // Match if all components are present
        $install_class and 
        all of ($hostname, $cwd, $username) and 
        $http_request
}