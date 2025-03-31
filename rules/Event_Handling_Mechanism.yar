rule Event_Handling_Mechanism {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious event handling mechanism that could be used for malicious purposes"
        confidence = "75"
        severity = "70"
    strings:
        $event_handle_map = "event_handle_map"
        $register_event = "register_event_handle("
        $get_subscriber = "get_event_subscriber("
    condition:
        all of them
}