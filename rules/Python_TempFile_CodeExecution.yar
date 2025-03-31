rule Python_TempFile_CodeExecution {
    meta:
        author = "RuleLLM"
        description = "Detects creation and execution of temporary files in Python"
        confidence = 85
        severity = 80
    strings:
        $tempfile = "NamedTemporaryFile"
        $write = ".write("
        $close = ".close()"
        $exec = "system("
    condition:
        all of them
}