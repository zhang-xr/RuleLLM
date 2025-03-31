rule Dynamic_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using eval or exec to dynamically execute code."
        confidence = 85
        severity = 80

    strings:
        $eval = "eval"
        $exec = "exec"
        $setattr = "setattr"

    condition:
        any of ($eval, $exec) and $setattr
}