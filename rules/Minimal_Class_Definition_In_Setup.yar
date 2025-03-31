rule Minimal_Class_Definition_In_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with minimal or suspicious class definitions"
        confidence = 85
        severity = 75

    strings:
        $class_def = /class\s+\w+\s*\(\)\s*:/
        $print = /print\s*\(['\"].*['\"]\)/

    condition:
        $class_def and $print
}