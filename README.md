armbin2elf: a bin2elf converter tool for 32-bit ARMs
====================================================

I wrote this tool in frustration after not finding an existing solution.

There are assorted "bin2elf" scripts online with magic sequences of invoking objcopy and ld, but I found them wholly inadequate.  Yes, they might create what is technically an ELF file, but it is one without much utility.  Their output lacks a valid entry address and fails to provide the necessary metadata to indicate THUMB or ARM mode.  As a result, tools like objdump are severely handicapped from providing useful information.

## Sample Usage

Say you have a binary image for a ARM Cortex-M that starts at 0x0000_0000.  The entry address is 0x101 (least significant bit is set, indicating THUMB mode).

```
armbin2elf output.elf 0x101 code.bin 0
```

Say you have a ARM Cortex-M with two binary images; one starts at 0x0000_0000 and the second starts at 0x1FFF_1800.  The entry address is 0x181 (least significant bit is set, indicating THUMB mode).

```
armbin2elf output.elf 0x181 first.bin 0x00000000 second.bin 0x1FFF1800
```

## Specifics

The tool adapts to the number of binary images supplies on the command line.

strtoul is used for all numerical command line arguments, so numbers can be expressed in decimal or hex.

The size of the binaries is automatically inferred by the file size.

If the least significant bit of the entry address is set, the sections are marked as THUMB mode (rather than ARM mode).  In the section containing the entry address, the THUMB/ARM hint is associated with that address; for any additional sections, the origin is used.
