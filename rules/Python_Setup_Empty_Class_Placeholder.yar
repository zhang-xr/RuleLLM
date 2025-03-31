rule Python_Setup_Empty_Class_Placeholder {
    meta:
        author = "RuleLLM"
        description = "Detects empty class definitions in Python setup scripts, which could indicate malicious placeholders"
        confidence = 75
        severity = 65

    strings:
        $empty_class = "class send():"
        $empty_init = "def __init__():"

    condition:
        $empty_class and $empty_init
}