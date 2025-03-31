rule Suspicious_Package_Setup_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that execute code during setup or egg_info operations"
        confidence = 85
        severity = 75
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass"
        $run_command = "def run(self):"
        $http_request = "requests.get"
    condition:
        $setup and 
        $cmdclass and 
        $run_command and 
        $http_request
}