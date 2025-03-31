rule Python_Subprocess_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious subprocess execution patterns in Python code"
        confidence = 80
        severity = 80
    strings:
        $subprocess = "import subprocess"
        $run = /subprocess\.run\(\[[^\]]+\]/
        $shell_true = "shell=True"
        $check_true = "check=True"
    condition:
        all of ($subprocess, $run) and any of ($shell_true, $check_true)
}