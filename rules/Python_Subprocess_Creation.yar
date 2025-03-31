rule Python_Subprocess_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts creating subprocesses, potentially for malicious execution"
        confidence = 75
        severity = 70

    strings:
        $subprocess_call = /subprocess\.(Popen|call|run)\(/
        $exec_function = "exec("

    condition:
        $subprocess_call and $exec_function
}