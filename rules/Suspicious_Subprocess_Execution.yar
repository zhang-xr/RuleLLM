rule Suspicious_Subprocess_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious subprocess execution in Python code"
        confidence = 85
        severity = 80
    strings:
        $subprocess_run = /subprocess\.run\(/
        $shell_true = /shell=True/
        $devnull = /stdout=subprocess\.DEVNULL/
    condition:
        $subprocess_run and $shell_true and $devnull
}