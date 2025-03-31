rule Shell_Command_Execution_In_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects shell command execution in Python setup scripts"
        confidence = 85
        severity = 75

    strings:
        $subprocess_call = "from subprocess import call"
        $shell_command1 = "call([f\"{_a} -m pip install pyprettifier\"], shell=True)"
        $shell_command2 = "call([f\"{_a} {_b}\"], shell=True)"

    condition:
        all of them
}