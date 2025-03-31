rule Obfuscated_Dictionary {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated dictionary usage"
        confidence = 85
        severity = 75

    strings:
        $dict = "dict" ascii
        $map = "map" ascii
        $lambda = "lambda" ascii
        $obfuscate = "obfuscate" ascii

    condition:
        all of them
}