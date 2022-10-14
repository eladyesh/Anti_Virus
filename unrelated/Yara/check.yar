rule rule1 : tag1
{
    meta:
        author = ""
        description = "rule description"
        date = "yyyy-mm-dd"
    strings:
        $str = "kernel32.dll" fullword ascii
        $a = "CreateFileA" fullword ascii
    condition:
        uint16(0) == 0x5A4D and ($str or $a)
}
