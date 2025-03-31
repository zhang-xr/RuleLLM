rule Malicious_Setuptools_Setup_Configuration {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup() configurations in setuptools, including command overrides."
        confidence = 85
        severity = 80

    strings:
        $setup_func = "setup("
        $cmdclass_override = "cmdclass={"
        $run_command = "def run(self):"
        $http_request = /requests\.get\(['\"].+?['\"]\)/

    condition:
        all of ($setup_func, $cmdclass_override, $run_command, $http_request)
}