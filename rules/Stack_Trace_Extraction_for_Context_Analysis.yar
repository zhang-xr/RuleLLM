rule Stack_Trace_Extraction_for_Context_Analysis {
    meta:
        author = "RuleLLM"
        description = "Detects code that extracts the call stack to analyze the import context"
        confidence = 85
        severity = 75
    strings:
        $traceback = "traceback.extract_stack()"
        $stack_info = "'file': frame.filename"
        $context = "find_import_context()"
    condition:
        all of them
}