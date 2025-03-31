rule Call_Stack_Analysis {
    meta:
        author = "RuleLLM"
        description = "Detects the extraction of the call stack, which could be used to understand execution context"
        confidence = 60
        severity = 40
    strings:
        $traceback = "traceback.extract_stack()"
        $stack_info = "stack_info.append"
    condition:
        $traceback and $stack_info
}