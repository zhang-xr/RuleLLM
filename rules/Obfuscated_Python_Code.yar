rule Obfuscated_Python_Code {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated Python code using lambda, map, and dict functions"
        confidence = 85
        severity = 75

    strings:
        $lambda_pattern = "lambda"
        $map_pattern = "map"
        $dict_pattern = "dict"
        $obfuscate_pattern = "obfuscate"

    condition:
        all of them
}