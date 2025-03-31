rule Suspicious_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious string manipulation patterns"
        confidence = 80
        severity = 85
    strings:
        $chr_array = /chr\(\d+\)/
        $join = "join"
        $lambda = "lambda"
        $random = "random"
        $int = "int"
    condition:
        $chr_array and $join and $lambda and $random and $int
}