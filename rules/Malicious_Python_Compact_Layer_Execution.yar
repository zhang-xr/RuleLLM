rule Malicious_Python_Compact_Layer_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that uses __COMPACT_LAYER to execute a binary"
        confidence = "95"
        severity = "85"

    strings:
        $compact_layer = "__COMPACT_LAYER=RunAsInvoker | start"

    condition:
        $compact_layer
}