rule Python_Package_Payload_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that downloads and executes a payload"
        confidence = 95
        severity = 90

    strings:
        $urllib_request = /urllib\.request\.urlopen\(/
        $write_binary = /with\s+open\([^,]+,\s*['"]wb['"]\)\s+as\s+\w+:/
        $subprocess_run = /subprocess\.run\(\["start",\s*[\w\.]+\],\s*shell=True\)/

    condition:
        all of them
}