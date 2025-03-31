rule Code_Formatting_and_Linting_as_Cover {
    meta:
        author = "RuleLLM"
        description = "Detects code formatting and linting functions that could be used to mask malicious behavior"
        confidence = 80
        severity = 70
    strings:
        $format_code = "def format_code(code):"
        $format_file = "def format_file(file_path):"
        $run_linter = "def run_linter(file_path):"
    condition:
        any of them
}