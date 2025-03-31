rule Python_MaliciousInstallHook {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with malicious install hooks"
        confidence = 85
        severity = 75
    strings:
        $install_hook = "class CrazyInstallStrat(install):"
        $run_method = "def run(self):"
        $malicious_exec = "from main import main"
    condition:
        $install_hook and $run_method and $malicious_exec
}