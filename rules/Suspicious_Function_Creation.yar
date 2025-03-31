rule Suspicious_Function_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious function creation and dynamic module import with base64 encoded strings"
        confidence = 90
        severity = 85

    strings:
        $doit_function = /def doit\(m,\s*f1,\s*f2\):/
        $import_module = /importlib\.import_module\(m\)/
        $getattr = /getattr\(module,\s*function_name\)/
        $base64_encode = /base64\.urlsafe_b64encode\([^)]+\)/

    condition:
        all of them
}