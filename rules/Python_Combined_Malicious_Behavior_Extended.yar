rule Python_Combined_Malicious_Behavior_Extended {
    meta:
        author = "RuleLLM"
        description = "Detects combined malicious behavior in Python scripts, including reverse shell and post-install command"
        confidence = 95
        severity = 100

    strings:
        $socket_import = "import socket"
        $os_import = "import os"
        $pty_import = "import pty"
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $dup2_call = "os.dup2"
        $pty_spawn = "pty.spawn(\"/bin/sh\")"
        $post_install_class = "class PostInstallCommand(install):"
        $run_method = "def run(self):"
        $install_call = "install.run(self)"

    condition:
        (all of ($socket_import, $os_import, $pty_import) and
         2 of ($socket_create, $dup2_call, $pty_spawn)) or
        (all of ($post_install_class, $run_method, $install_call))
}