rule Python_Subprocess_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using subprocess to execute downloaded files"
        confidence = 85
        severity = 75

    strings:
        $subprocess = "subprocess"
        $run = ".run("
        $url = /https?:\/\/[^\s]+/
        $exe = /\.exe/

    condition:
        all of ($subprocess, $run) and any of ($url, $exe)
}