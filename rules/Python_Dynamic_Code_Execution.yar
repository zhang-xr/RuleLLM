rule Python_Dynamic_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using exec or eval for dynamic code execution"
        confidence = 85
        severity = 80

    strings:
        $exec = "exec"
        $eval = "eval"

    condition:
        any of ($exec, $eval)
}