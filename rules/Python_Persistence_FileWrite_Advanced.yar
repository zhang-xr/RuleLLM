rule Python_Persistence_FileWrite_Advanced {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python file writing for persistence with advanced indicators"
        confidence = 85
        severity = 90
        reference = "Analysis of malicious Python package"
    
    strings:
        $file_write = "file = open(\"remote-access.py\", \"w\")" ascii wide
        $file_move = /os\.rename\(\"remote-access\.py\",/ ascii wide
        $subprocess_exec = /subprocess\.Popen\(\[[\"']python3[\"'],/ ascii wide
    
    condition:
        all of ($file_write, $file_move, $subprocess_exec)
}