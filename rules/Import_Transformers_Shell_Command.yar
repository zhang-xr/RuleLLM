rule Import_Transformers_Shell_Command {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to import 'transformers' followed by execution of a shell command, indicating potential malicious behavior."
        confidence = 85
        severity = 75

    strings:
        $import_transformers = "importlib.import_module('transformers')"
        $os_system = "os.system"
        $shell_command = /os\.system\([\'\"][a-zA-Z0-9_\-\.\s]+[\'\"]\)/

    condition:
        all of ($import_transformers, $os_system, $shell_command)
}