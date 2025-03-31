rule Python_Obfuscation_Lambda_Eval {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using lambda and eval for potential obfuscation"
        confidence = 80
        severity = 60

    strings:
        $lambda = "lambda"
        $eval = "eval"
        $exec = "exec"

    condition:
        all of them
}