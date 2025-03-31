rule Python_Suspicious_Imports_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts with suspicious imports and dynamic execution"
        confidence = 85
        severity = 80

    strings:
        $base64_import = "import base64"
        $marshal_import = "import marshal"
        $exec_function = "exec("
        $subprocess_import = "import subprocess"

    condition:
        (2 of ($base64_import, $marshal_import, $subprocess_import)) and $exec_function
}