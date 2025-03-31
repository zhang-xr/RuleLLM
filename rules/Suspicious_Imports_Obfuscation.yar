rule Suspicious_Imports_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious imports (e.g., pycryptodome) combined with obfuscation"
        confidence = 75
        severity = 70

    strings:
        $import_pycryptodome = "#pip install pycryptodome"
        $obfuscate_pattern = "pyobfuscate="
        $lambda_pattern = /lambda\s+\w+,\s*\w+:/

    condition:
        $import_pycryptodome and 
        $obfuscate_pattern and 
        $lambda_pattern
}