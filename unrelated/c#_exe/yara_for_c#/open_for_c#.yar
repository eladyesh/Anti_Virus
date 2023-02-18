rule create_file
{
    meta:
        description = "Detects a create call"
        author = "Elad Yesh"
    strings:
        // $filename = "MyTest.txt"
        $file_create_call = "File"
        $create_call = "Create"

    condition:
        uint16(0) == 0x5A4D and $create_call and $file_create_call
}

rule write_to_file
{
    meta:
        description = "Detects a write call"
        author = "Elad Yesh"
    strings:
        $add_text = "AddText"
        // $subset_of_characters = "\r\n\r\nThe following is a subset of characters:\r\n"

    condition:
        $add_text // $subset_of_characters
}

rule read_file
{
    meta:
        description = "Detects a read call"
        author = "Elad Yesh"
    strings:
        $open_call = "OpenRead"

    condition:
        $open_call
}

rule txt_file_name_in_exe {
    meta:
        description = "Matches any string containing '.txt' within an exe file"
    strings:
        $txt_file_name = /.*\.txt/ wide nocase
    condition:
        $txt_file_name
}
