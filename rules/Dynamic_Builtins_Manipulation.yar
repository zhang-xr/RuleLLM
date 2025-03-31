rule Dynamic_Builtins_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic manipulation of builtins (e.g., eval, exec)"
        confidence = 80
        severity = 85

    strings:
        $setattr_pattern = "setattr(__builtins__,"
        $exec_pattern = "exec("
        $eval_pattern = "eval("

    condition:
        $setattr_pattern and 
        any of ($exec_pattern, $eval_pattern)
}