rule Conditional_Malicious_Import {
    meta:
        author = "RuleLLM"
        description = "Detects conditional import patterns followed by malicious shell command execution."
        confidence = 85
        severity = 75

    strings:
        $import_transformers = "importlib.import_module('transformers')"
        $os_system = "os.system"
        $curl_pattern = "curl http://"
        $sh_pattern = "|sh"

    condition:
        $import_transformers and $os_system and ($curl_pattern or $sh_pattern)
}