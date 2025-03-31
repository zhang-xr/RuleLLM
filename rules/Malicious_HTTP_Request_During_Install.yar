rule Malicious_HTTP_Request_During_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts making HTTP requests during package installation"
        confidence = 95
        severity = 85
    strings:
        $setup = "setup("
        $http_request = "requests.get"
        $run_command = "def run(self):"
    condition:
        $setup and 
        $http_request and 
        $run_command
}