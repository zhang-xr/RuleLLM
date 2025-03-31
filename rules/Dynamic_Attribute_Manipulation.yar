rule Dynamic_Attribute_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic modification of built-in functions using setattr"
        confidence = 90
        severity = 85

    strings:
        $setattr_pattern = "setattr"
        $builtins_pattern = "__builtins__"
        $exec_pattern = "exec"
        $eval_pattern = "eval"

    condition:
        all of ($setattr_pattern, $builtins_pattern) and
        any of ($exec_pattern, $eval_pattern)
}