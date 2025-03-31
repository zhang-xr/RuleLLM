rule Python_Post_Install_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that override the install command to execute additional code post-installation."
        confidence = "90"
        severity = "80"
    
    strings:
        $class_def = "class Trace(install):"
        $run_method = "def run(self):"
        $install_call = "install.run(self)"
        $subprocess_call = "subprocess.call"
    
    condition:
        all of them
}