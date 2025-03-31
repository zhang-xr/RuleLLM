rule Malicious_PostInstall_ShellExecution {
    meta:
        author = "RuleLLM"
        description = "Detects custom post-install hooks with shell command execution in Python setup scripts"
        confidence = 90
        severity = 80

    strings:
        $install_class = "class install(_install):"
        $post_install_func = "def _post_install(dir):"
        $shell_call = /call\(\[f".*"\], shell=True\)/
        $sys_executable = "sys.executable"
        $os_path_join = "os.path.join"

    condition:
        filesize < 10KB and
        all of them
}