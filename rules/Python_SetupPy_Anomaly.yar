rule Python_SetupPy_Anomaly {
    meta:
        author = "RuleLLM"
        description = "Detects anomalous patterns in setup.py files"
        confidence = "80"
        severity = "80"
    
    strings:
        $setup2 = "from setuptools import setup"
        $exec3 = "exec("
        $system3 = "system("
        $tempfile3 = "NamedTemporaryFile"
        $urlopen2 = "urlopen("
        
    condition:
        $setup2 and 
        (
            ($exec3 and $system3) or
            ($tempfile3 and $urlopen2)
        )
}