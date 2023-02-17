rule detect_with_open_call
{
    strings:
        $with_open_call = "with open(" wide
        $filename = /with open\("([^\)]+)"/ wide
        $mode = /with open\("[^"]+", "([^\)]+)"/ wide

    condition:
        $with_open_call and $filename and $mode
}
