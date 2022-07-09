# APPNOTE.TXT Google CTF 2022
## MISC - Malformed ZIP - 210 solves - 50 points

This challenge is a classic kind of CTF challenge in which we are given a corrupted or malformed .ZIP file and we have to retrieve a secret from it. The name references the [APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) file which contains the .ZIP File Format Specification.

A .ZIP file will have several sections, headers and data. Each header starts with a known 4 byte signature followed by fixed length fields and few variable length fields. Different signatures specify different type of headers which hold different fields.

A basic .ZIP file will have the files one after the other, each prefixed by it's own Local File Header (LFH). Following this section will come the Central Directory Headers (CDH) for each file. And at the end will come the End of Central Directory Record (ECDR).

![ZIP file format specification](https://github.com/sudoaza/CTF_writeups/blob/main/img/zip_specification.png?raw=true)

If we simply try to extract the file we get a hello.txt file with "There's more to it than meets the eye..." and if we run strings on the ZIP file we can see there is another hi.txt file with "Find a needle in the haystack..." and lots of flag## strings from flag00 to flag18. And if we simply try to get each file data following a LFH we would find that for each file name there is 36 possible files with the letters a..z, C, T, F, 0, 1, 3, 7, {, }, _. 

We can further inspect the file and see what headers are there, if we search the LFH signature "PK\x01\x02" we find 686 hits, the 2 for the text files and 19 * 36 for all the possible letters of the flag. Searching for the CDH signature "PK\x03\x04" again returns 686 results. Finally searching for the ECDR "PK\x05\x06" we get 21 hits. That's 2 for the text files and 19 for our flag! (As a margin note, each ECDR is inside the comment field of the previous ECDR but we don't care and neither does most extractor programs).

```bash
$ pcregrep -aoM $'PK\1\2' dump.zip | wc -l        
686
$ pcregrep -aoM $'PK\3\4' dump.zip | wc -l
686
$ pcregrep -aoM $'PK\5\6' dump.zip | wc -l
21
```

The ECDR, among other fields, contains the size in bytes of the Central Directory and the offset bytes from the beginning of the file, both as 4 byte little-endian integers. So at offset bytes from the start will find the corresponding CDH. The CDH has many fields including the relative offset of local header, which again gives the offset from the beginning of the file to the corresponding LFH. Also both the CDH and the LFH have the compression method fields set to "\x00\x00", which is no compression. And after the LFH comes our data.

End of Central Dir Record => Central Dir Header => Local File Header => Data

```python
import re
content = open('dump.zip','rb').read()

def parse_int(b):
  return int.from_bytes(b,'little')

# Search for End of Central Directory Record
for m in re.finditer(b"PK\5\6", content):
  i = m.start()

  # Parse End of Central Directory Record
  cent_dir_offset= parse_int(content[i+16:i+20])

  # Parse Central Directory Header
  local_header_offset= parse_int(content[cent_dir_offset+42:cent_dir_offset+42+4])

  # Parse Local File Header
  compressed_size = parse_int(content[local_header_offset+18:local_header_offset+22])
  file_name_length = parse_int(content[local_header_offset+26:local_header_offset+28])
  content_start = local_header_offset+30+file_name_length
  comp_content = content[content_start:content_start+compressed_size]
  print(comp_content.decode("ascii"),end="")
```

We get CTF{p0s7m0d3rn_z1p}
