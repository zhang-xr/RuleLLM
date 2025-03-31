rule Obfuscated_Function_Calls {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated function calls in Python scripts"
        confidence = "80"
        severity = "75"
    
    strings:
        $doit_function = "def doit(m, f1, f2):"
        $importlib_call = "importlib.import_module(m)"
        $getattr_call = "getattr(module, function_name)"
    
    condition:
        all of them
}