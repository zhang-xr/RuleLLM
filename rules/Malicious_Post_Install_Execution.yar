rule Malicious_Post_Install_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects custom post-installation execution in Python setup scripts"
        confidence = 90
        severity = 80

    strings:
        $install_class = "class install(_install):"
        $post_install_func = "def _post_install(dir):"
        $execute_call = "self.execute(_post_install, (self.install_lib,), msg=\"Running post install task\""
        $shell_call = "call([f\"{_a} -m pip install pyprettifier\"], shell=True)"

    condition:
        all of them
}