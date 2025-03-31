rule Windows_ReverseShell_Threaded {
    meta:
        author = "RuleLLM"
        description = "Detects Windows-specific reverse shell using threaded process communication"
        confidence = 90
        severity = 85
    
    strings:
        $cmd_process = /subprocess\.Popen\(\["cmd","\/K","cd \.{3}\/\.{3}\/\.{3}"\]/
        $thread_create = "threading.Thread(target=host2remote"
        $stdin_write = "p.stdin.write(s.recv(1024).decode())"
        $stdout_read = "s.send(p.stdout.read(1).encode())"
    
    condition:
        3 of them
}