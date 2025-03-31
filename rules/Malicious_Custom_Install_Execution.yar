rule Malicious_Custom_Install_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects custom install command that executes malicious code during installation"
        confidence = "90"
        severity = "90"
    
    strings:
        $class_def = "class InstallCommand(install):"
        $run_method = "def run(self):"
        $custom_exec = "CustomRun(path_bytes)"
        $subprocess = "subprocess.Popen([binary_path]"
    
    condition:
        all of them
}