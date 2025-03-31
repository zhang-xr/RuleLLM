rule Malicious_Package_Installation {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation that executes code during setup"
        confidence = 95
        severity = 90
    strings:
        $class_def = "class CrazyInstallStrat(install):"
        $run_method = "def run(self):"
        $import_main = "from main import main"
        $main_exec = "main()"
    condition:
        all of them
}