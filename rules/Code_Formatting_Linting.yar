rule Code_Formatting_Linting {
    meta:
        author = "RuleLLM"
        description = "Detects the presence of code formatting and linting utilities, which could be used to obfuscate malicious code"
        confidence = 50
        severity = 30
    strings:
        $format_code = "def format_code("
        $run_linter = "def run_linter("
        $trailing_whitespace = "check_trailing_whitespace"
    condition:
        any of ($format_code, $run_linter, $trailing_whitespace)
}