rule Combined_Malicious_Activity {
    meta:
        author = "RuleLLM"
        description = "Detects the combination of metadata token exfiltration and abuse of setuptools commands."
        confidence = "90"
        severity = "95"

    strings:
        $metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
        $setup_tools = "from setuptools import setup"
        $command_override = /class\s+\w+\((\w+)\):\s+def\s+run\(self\):/
        $malicious_call = /custom_command\(\)/

    condition:
        all of them
}