rule Dynamic_Function_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic function execution using eval() or exec()."
        confidence = 90
        severity = 85

    strings:
        $eval = "eval("
        $exec = "exec("
        $dynamic_call = /\(.*\)\(.*\)/

    condition:
        ($eval or $exec) and 
        $dynamic_call
}