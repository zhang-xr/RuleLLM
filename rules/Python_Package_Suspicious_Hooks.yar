rule Python_Package_Suspicious_Hooks {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious command hooks in Python package setup"
        confidence = 85
        severity = 90
    strings:
        $hook_pattern = /cmdclass\s*=\s*\{[^}]*(develop|install)[^}]*execute\(\)/ ascii
        $setup_pattern = /setup\([^\)]+cmdclass\s*=/ ascii
        $exec_pattern = /\.run\(self\)\s*:\s*execute\(\)/ ascii
    condition:
        $setup_pattern and 
        (any of ($hook_pattern, $exec_pattern))
}