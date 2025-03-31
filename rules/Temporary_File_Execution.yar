rule Temporary_File_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects creation and execution of temporary files in Python code"
        confidence = 88
        severity = 92

    strings:
        $tempfile = "NamedTemporaryFile"
        $write = "write"
        $close = "close"
        $system = "system"

    condition:
        all of ($tempfile, $write, $close, $system)
}