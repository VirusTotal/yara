Office Open XML, also known as OpenXML or OOXML, is an XML-based format for office documents that was developed by Microsoft and later adopted/standardised by ISO and IEC as ISO/IEC 29500. OOXML is now the default format of all Microsoft Office documents (.docx, .xlsx, and .pptx). There is a difference between Transitional variation that Microsoft use and the Strict variation that can be used as an open standard for documents.  

OOXML files (such as `.docx`, `.xlsx`, and `.pptx`) are essentially ZIP archives that bundle multiple XML files, media files, and other resources together into a single package and thereby follow the Open Packaging Conventions (OPC) standard, which uses the ZIP container format. Older document formats may also support OOXML format.

The inspiration behind the development of the ooxml module was to focus on modern documents often used by adversaries during initial access as droppers or downloaders for next stage payloads. Hence, efforts have been made to differentiate ooxml files from wider PKZip files that are not necessarily documents. 

The module is built using the specification listed here https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html through incorporation of the end of central directory record and central directory file headers for each entry in central directory. It performs header and trailer check for the PKZIP signature but also optionally checks for the presence of Content_Types.xml which is listed in the first few entries of the central directory using the is_ooxml Boolean property in the module.

The module does not extract the identified file entries from the central directory but rather relies on the metadata surrounding the entries.
## Module Structure

type is_ooxml
Return true if file matches characteristics of an OOXML file.  
*Example: ooxml.is_ooxml*

type number_of_on_disk_entries
The number of entries in the central directory on this disk.
*Example: ooxml.number_of_on_disk_entries == 15*

type number_of_total_entries
Total number of entries in the central directory.
*Example: ooxml.number_of_total_entries == 13*

**NOTE:** Typically the value of number_of_on_disk_entries and number_of_total_entries should be identical

type central_dir_size
Size of the central directory in bytes.
*Example: ooxml.central_dir_size < 4KB*

type central_dir_offset
Raw offset of the start of central directory on the disk.
*Example: ooxml.central_dir_offset == 0x3220* 

type zip_comment_len
The length of the ZIP comment field in Bytes.
*Example: ooxml.zip_comment_len > 0*

type zip_comment_str
Optional comment for the Zip file.
*Example: ooxml.zip_comment_str == "Some Random Zip Comment"*

**NOTE:** Two attributes from the end of central directory record (Disk Number and Disk # w/cd) were intentionally ignored due to irrelevance of their corresponding values.

type entries
A zero-based array of central directory entries, one for each entry the PKZIP has. Individual entries can be accessed by using the [ ] operator. Each central directory record has the following attributes:

**NOTE:** In the module, no limits have been set to restrict the scanning of a given number of entries to avoid those bloated or corrupted PKZIP files which have a significant higher number of entries (i.e. more than 100)

type name_string
Entry's name.
*Example: ooxml.entries[0].name_string == "[Content_Types].xml"*

type name_length
Entry's  name length in bytes.
*Example: ooxml.entries[0].name_length == 19*

type compressed_size 
Compressed size of the Entry in Bytes.
*Example: ooxml.entries[3].compressed_size > 250*

type uncompressed_size
Uncompressed size of the Entry in Bytes.
*Example: ooxml.entries[3].compressed_size == 252*

type crc32_checksum
Value computed over file data of an entry by CRC-32 algorithm with 'magic number' 0xdebb20e3 (little endian).
*Example: ooxml.entries[5].crc32_checksum == 0x4CE962CA*

type compression_method_value UNTIL HERE
Raw value of the compression method used on the entry.
*Example: ooxml.entries[6].compression_method_value == 0x08 //Deflated*

type compression_method_name 
Derived name of the compression method used on the entry based on the mappings defined in the PKZIP specification.
*Example: ooxml.entries[6].compression_method_name == "Deflated"*

type mod_time_raw
Entry's modification time stored in standard MS-DOS format.
*Example: ooxml.entries[7].mod_time_raw == 0x7d1c //15:40:36*

type mod_date_raw
Entry's modification date stored in standard MS-DOS format.
*Example: ooxml.entries[7].mod_time_raw == 0x354b //10/11/2006*

type flags
Raw value of general purpose bit flag for the entry

type version_made_by
Raw value that constitutes the OS name and ZIP specification version used to create the entry. Upper Byte provides the OS name and lower Byte gives the ZIP version.
*Example: ooxml.entries[8].version_made_by == 0x0317 //03 -> UNIX  INT 23 -> 2.3*

type os_name
OS name used to create the entry which is derived from the  version_made_by raw value and the specificaiton mappings related to it.
*Example: ooxml.entries[8].os_name == "Unix"*

type spec_version
Raw value of ZIP specification version which is derived from the version_made_by raw value.
*Example: ooxml.entries[8].spec_version == 22 //2.2*

type version_needed
PKZip version needed to extract the entry
*Example: ooxml.entries[8].version_needed == 20 //2.0*

**NOTE:** Typically version_needed is equal to spec_version

## Mappings

Following mappings are for the compression_method_name and os_name

*compression_method_name*

	  {8, "Deflate"},
    {0, "Store"},    
    {9, "Deflate64"},
    {14, "LZMA"},
    {12, "BZIP2"},
    {1, "Shrink"},
    {2, "Reduce1"},
    {3, "Reduce2"},
    {4, "Reduce3"},
    {5, "Reduce4"},
    {6, "Implode"},
    {98, "PPMd"},
    {19, "LZ77"},
    {0, NULL}

*os_name*

	  {0, "FAT"},
    {1, "Amiga"},
    {2, "VMS"},
    {3, "Unix"},
    {4, "VM/CMS"},
    {5, "Atari ST"},
    {6, "HPFS"},
    {7, "Macintosh"},
    {10, "NTFS"},
    {11, "MVS"},
    {14, "VFAT"},
    {18, "IBM OS/2"},
    {19, "Macintosh OSX"},
    {0, NULL}
    

**NOTE:** Extra field length, File comment length, Internal/External file attributes, Extra field and file comment are yet to be implemented in the module. The rest of the properties from PKZIP specification were intentionally left out. Additionally, the modification date and time will be parsed into human readable timestamps.





