rule Suspicious_Lambda_Map {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of lambda and map functions"
        confidence = 85
        severity = 75

    strings:
        $lambda = "lambda" ascii
        $map = "map" ascii
        $dict = "dict" ascii
        $obfuscate = "obfuscate" ascii

    condition:
        all of them
}