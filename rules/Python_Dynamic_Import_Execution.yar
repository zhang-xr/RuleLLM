rule Python_Dynamic_Import_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic import and execution of functions using string concatenation, commonly used in malicious Python scripts."
        confidence = 90
        severity = 80

    strings:
        $func_def = "def imp_and_run(m, f1, f2):"
        $importlib = "importlib.import_module"
        $getattr = "getattr(module, function_name)"
        $dynamic_call = /importlib\.import_module\([^\)]+\)/

    condition:
        all of them
}