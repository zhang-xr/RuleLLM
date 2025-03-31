rule Malicious_RunCommand_Function {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of a malicious RunCommand function used in setuptools command overrides."
        confidence = 80
        severity = 75

    strings:
        $run_command_func = "def RunCommand():"
        $http_request = /requests\.get\(['\"].+['\"]\)/
        $print_message = /print\(['\"].+p0wnd!?['\"]\)/

    condition:
        all of them
}