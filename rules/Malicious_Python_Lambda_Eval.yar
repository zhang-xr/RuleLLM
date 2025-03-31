rule Malicious_Python_Lambda_Eval {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using lambda functions and eval for dynamic code execution"
        confidence = 95
        severity = 90

    strings:
        $lambda_eval = /_=lambda\s+.*eval\(.*\)/
        $eval_hex = /\x65\x76\x61\x6c/  // Hex representation of "eval"
        $chr_join = /chr\(.*\).join\(/

    condition:
        all of them
}