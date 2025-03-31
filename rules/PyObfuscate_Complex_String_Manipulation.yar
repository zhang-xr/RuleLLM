rule PyObfuscate_Complex_String_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects complex string manipulation patterns often used in obfuscated Python code"
        confidence = 85
        severity = 75
        
    strings:
        $complex_string = /[^\x00-\x7F]{20,}/
        $replace_call = ".replace("
        $lambda_function = "lambda map,dict"
        $dict_creation = "dict(map(lambda"
        
    condition:
        all of them
}