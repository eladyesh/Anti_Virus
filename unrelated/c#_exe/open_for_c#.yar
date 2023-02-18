rule create_file
{
    strings:
        $filename = "MyTest.txt"
        $create_call = "Create"

    condition:
        $filename or $create_call
}

rule write_to_file
{
    strings:
        $add_text = "AddText"
        $subset_of_characters = "\r\n\r\nThe following is a subset of characters:\r\n"

    condition:
        $add_text or $subset_of_characters
}

rule read_file
{
    strings:
        $open_call = "OpenRead"

    condition:
        $open_call
}
