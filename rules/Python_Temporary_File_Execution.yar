rule Python_Temporary_File_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that create and execute temporary files"
        confidence = 85
        severity = 90

    strings:
        $tempfile = "from tempfile import NamedTemporaryFile"
        $write = "_ttmp.write"
        $close = "_ttmp.close"
        $system = "_ssystem"
        $exec = "exec("

    condition:
        all of them and
        filesize < 10KB
}