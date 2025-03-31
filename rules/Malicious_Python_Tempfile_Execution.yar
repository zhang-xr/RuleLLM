rule Malicious_Python_Tempfile_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects creation and execution of temporary Python files"
        confidence = 92
        severity = 88

    strings:
        $tempfile = "__import__('tempfile').NamedTemporaryFile"
        $write = ".write("
        $close = ".close()"
        $system = "__import__('os').system"

    condition:
        all of them
}