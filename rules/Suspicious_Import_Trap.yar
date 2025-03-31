rule Suspicious_Import_Trap {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious import traps with malicious fallback behavior"
        confidence = 80
        severity = 85
    strings:
        $importlib_import = "importlib.import_module"
        $os_system = "os.system"
        $try_block = "try:"
    condition:
        $try_block and $importlib_import and $os_system
}