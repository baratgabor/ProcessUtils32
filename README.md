## ProcessUtils32

Simple utility class that uses various PInvoke functions to read information from the virtual address space of other running processes. **Compatible only with 32 bit processes.**

Main features:
- Getting the address of the **ThreadStack0** symbol used by CheatEngine
- Following pointer chains, and reading a result into a chosen type

I'll probably convert it sometime to use unsafe code and pointers, plus I'll write a 64 bit equivalent.

*I used this class to read data from an app that was written in an unintentionally cryptic way, lacking any interop capabilities, and being completely inaccessible by UIA and MSAA.*
