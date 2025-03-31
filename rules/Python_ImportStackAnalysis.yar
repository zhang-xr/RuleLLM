rule Python_ImportStackAnalysis {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that analyzes import stack and context"
        confidence = 85
        severity = 70
    strings:
        $traceback = "traceback.extract_stack()"
        $site_packages = "\"site-packages\" in frame.filename"
        $dist_packages = "\"dist-packages\" in frame.filename"
        $stack_info = "stack_info.append"
        $import_context = "find_import_context"
    condition:
        all of ($traceback, $stack_info) and
        2 of ($site_packages, $dist_packages, $import_context)
}