rule Python_RemoteCodeExecution_SetupPy {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files containing remote code execution patterns"
        confidence = "90"
        severity = "90"
    
    strings:
        $setup1 = "from setuptools import setup"
        $system1 = "system("
        $urlopen1 = "urlopen("
        $exec1 = "exec("
        $tempfile1 = "NamedTemporaryFile"
        $write1 = ".write(b\"\"\""
        
    condition:
        all of ($setup1, $system1) and 
        2 of ($urlopen1, $exec1, $tempfile1, $write1)
}