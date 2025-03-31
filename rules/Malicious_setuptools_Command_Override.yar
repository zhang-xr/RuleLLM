rule Malicious_setuptools_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects the overriding of setuptools commands (install, develop, egg_info) to execute malicious code."
        confidence = "85"
        severity = "80"

    strings:
        $setup_tools = "from setuptools import setup"
        $command_override = /class\s+\w+\((\w+)\):\s+def\s+run\(self\):/
        $malicious_call = /custom_command\(\)/

    condition:
        all of them
}