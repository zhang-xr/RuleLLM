rule Command_Execution_Subprocess {
    meta:
        author = "RuleLLM"
        description = "Detects execution of system commands and subprocess usage"
        confidence = 80
        severity = 75

    strings:
        $subprocess_run = "subprocess.run"
        $capture_output = "capture_output=True"
        $check_true = "check=True"
        $command_execution = /subprocess\.run\([^)]+\)/

    condition:
        all of ($subprocess_run, $capture_output, $check_true) or 
        $command_execution
}