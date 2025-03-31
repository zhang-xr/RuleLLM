rule Post_Install_Malicious_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects custom install class for post-install malicious execution"
        confidence = 90
        severity = 85

    strings:
        $class_def = "class CrazyInstallStrat(install):"
        $run_method = "def run(self):"
        $import_main = "from main import main"
        $exec_main = "main()"

    condition:
        $class_def and $run_method and $import_main and $exec_main
}