rule Python_Suspicious_Class_Structure {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious empty class and method definitions in Python code"
        confidence = "80"
        severity = "85"
    strings:
        $empty_class = "class send():"
        $empty_init = "def __init__():"
    condition:
        $empty_class and $empty_init
}