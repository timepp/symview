module main;

import std.stdio;
import std.getopt;
import std.file;
import std.path;
import std.utf;
import std.conv;
import core.stdc.time;
import std.datetime;
import core.runtime;
import core.sys.windows.windows;
import timeppdbghelp;

HANDLE process_handle;
bool verbose = true;
DbgHelp* dbghlp;

struct SymInfo
{
    string name;
    string srcfile;
    int    srcline;
    ulong  addr;
    size_t len;
    uint   tag;
};

int main(string[] args)
{
    dbghlp = DbgHelp.get();
    process_handle = GetCurrentProcess();

    writeln("symview: convert information in pdb file to readable csv format.");
	writeln("written in D programming language.");

    getopt(args, "verbose|v", &verbose);

    dbghlp.SymInitialize(process_handle, null, false);
    scope(exit) dbghlp.SymCleanup(process_handle);

    dbghlp.SymSetOptions(0 | SYMOPT_LOAD_LINES);

    for (uint i = 1; i < args.length; i++)
    {
        auto syms = processfile(args[i]);
        SaveToCSV(syms);
    }
    
    return 0;
}

struct SymEnumContext
{
    SymInfo[] syms;
    DWORD fileSize;
    DWORD64 baseAddress;
    time_t lastProgressTime;
    int symCount;
};

SymInfo[] processfile(string path)
{
    writefln("processing %s", path);
    string dir = dirName(path);

    dbghlp.SymSetSearchPath(process_handle, toUTF16z(dir));

    HANDLE f = CreateFileW(toUTF16z(path), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    scope(exit) CloseHandle(f);

    auto len = GetFileSize(f, null);

    auto base = dbghlp.SymLoadModule64(process_handle, f, null, null, 0x10000000, len);
    scope(exit) dbghlp.SymCleanup(process_handle);

    SymEnumContext context;
    context.baseAddress = base;
    context.fileSize = len;
    
	writeln("begin enum symbols.");
    dbghlp.SymEnumSymbols(process_handle, base, null, cast(SymEnumFunc*)&EnumFunc, &context);
	writeln("end enum symbols.");

    return context.syms;
}

void SaveToCSV(SymInfo[] syms)
{
}

extern (Windows)
{
    BOOL EnumFunc(SYMBOL_INFOW* info, ULONG len, PVOID param)
    {
		string s();

		/*
        SymEnumContext* context = cast(SymEnumContext*)param;
        SymInfo sym;
        sym.tag = info.Tag;
        sym.len = len > 0 ? len : info.Size;
        sym.addr = info.Address - context.baseAddress;
        sym.srcline = 0;ff

        // undercorate
        string undname = toUTF8(info.Name);
        if (undname[0] == '?')
        {
            if (undname[0..4] == "??_C@")
            {
            }
            else
            {
            }
        }

        sym.name = undname;

        context.symCount++;
        context.syms ~= sym;
		*/
        return TRUE;
    }
}

