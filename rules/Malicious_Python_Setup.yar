rule Malicious_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that include suspicious code execution patterns."
        confidence = 85
        severity = 90

    strings:
        $setup = "from setuptools import setup"
        $exec = "exec(urlopen"
        $system = "system(f\"start {_eexecutable.replace('.exe', 'w.exe')}"
        $tempfile = "NamedTemporaryFile"

    condition:
        $setup and ($exec or $system or $tempfile)
}