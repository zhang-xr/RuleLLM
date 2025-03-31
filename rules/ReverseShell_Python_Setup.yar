rule ReverseShell_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py containing reverse shell code with custom install command"
        confidence = 95
        severity = 90
    
    strings:
        $cmd_class = "class execute(install)"
        $setup_call = /setup\s*\([^)]*cmdclass\s*=\s*{'install'\s*:\s*execute\s*}/
        $remote_access = "getRemoteAccess()"
        $socket_import = "import socket,subprocess,os,threading,sys,time"
    
    condition:
        all of them
}