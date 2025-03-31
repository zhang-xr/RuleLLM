rule MaliciousSetupPy_CommandExecution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious command execution in setup.py during egg_info phase"
        confidence = 90
        severity = 80

    strings:
        $cmd1 = "os.system(\"echo 'You Have been pwned' > /tmp/pwned\")"
        $cmd2 = "os.system(" ascii wide
        $egg_info = "class RunEggInfoCommand(egg_info):"
        $setup = "setup("

    condition:
        all of ($cmd1, $egg_info, $setup) or
        (all of ($cmd2, $egg_info, $setup) and $cmd2 in (0..100))
}