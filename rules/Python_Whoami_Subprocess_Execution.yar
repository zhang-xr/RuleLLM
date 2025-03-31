rule Python_Whoami_Subprocess_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects the use of subprocess to run the whoami command in Python"
        confidence = 80
        severity = 70

    strings:
        $whoami_command = /subprocess\.run\(\[.*\"whoami\".*\]\,.*capture_output\s*\=\s*True/

    condition:
        $whoami_command
}