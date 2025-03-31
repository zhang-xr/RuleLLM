rule Malicious_Function_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects execution of malicious functions in Python code"
        confidence = 75
        severity = 80

    strings:
        $os_import = "import os"
        $system_call = "os.system"
        $malicious_function = /def\s+\w+\(\):.*os\.system\(.*\)/

    condition:
        all of ($os_import, $system_call) and
        $malicious_function
}