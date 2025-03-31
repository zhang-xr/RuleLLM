rule Python_MaliciousSetup {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that misuse the setup() function to disguise malicious behavior."
        confidence = 80
        severity = 75

    strings:
        $setup = "setup("
        $tempfile = "NamedTemporaryFile"
        $system = "system"
        $exec = "exec"

    condition:
        all of ($setup) and 
        (1 of ($tempfile, $system, $exec)) and 
        filesize < 10KB
}