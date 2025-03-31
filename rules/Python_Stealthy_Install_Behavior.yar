rule Python_Stealthy_Install_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package installation behavior in Python setup.py"
        confidence = 80
        severity = 70
    strings:
        $install_override = "cmdclass={'install':"
        $subprocess = "subprocess.call"
        $sys_exec = "sys.executable"
        $hidden_exec = /-\w\s*"[\w\.]+"/
    condition:
        all of them and 
        filesize < 10KB
}