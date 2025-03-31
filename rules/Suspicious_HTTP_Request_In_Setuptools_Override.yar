rule Suspicious_HTTP_Request_In_Setuptools_Override {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests within setuptools command overrides, indicating potential malicious behavior."
        confidence = 95
        severity = 90

    strings:
        $http_request = /requests\.get\(['\"].+?['\"]\)/
        $cmdclass_override = "cmdclass={"
        $run_command = "def run(self):"

    condition:
        all of ($http_request, $cmdclass_override, $run_command)
}