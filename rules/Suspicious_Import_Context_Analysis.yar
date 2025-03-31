rule Suspicious_Import_Context_Analysis {
    meta:
        author = "RuleLLM"
        description = "Detects code analyzing import context and stack trace"
        confidence = 80
        severity = 70
    strings:
        $traceback = "traceback.extract_stack()"
        $stack_analysis = "find_import_stack()"
        $context_analysis = "find_import_context()"
        $site_packages = "site-packages"
    condition:
        $traceback and
        ($stack_analysis or $context_analysis) and
        $site_packages
}