rule Obfuscated_Lambda_Eval_Usage {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated Python code using lambda and eval/exec for dynamic code execution"
        confidence = 95
        severity = 90

    strings:
        $lambda_pattern = "lambda"
        $eval_pattern = "eval"
        $exec_pattern = "exec"
        $chr_pattern = "chr"
        $join_pattern = "join"

    condition:
        all of ($lambda_pattern, $eval_pattern, $chr_pattern, $join_pattern) or
        all of ($lambda_pattern, $exec_pattern, $chr_pattern, $join_pattern)
}