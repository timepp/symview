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
import core.stdc.string;
import timeppdbghelp;
import std.string;
import std.algorithm;

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

string FromCStr(wchar* cstr)
{
    immutable wchar* icstr = cast(immutable wchar*) cstr;
    wstring str = icstr[0..wcslen(icstr)];
    return to!string(str);
}

string UndecorateConstantString(string name)
{
    name = name[6..$];
    bool ansi = (name[0] == '0');
    bool extraAt = (name[1] < '0' || name[1] > '9');
    auto index = name.indexOf('@');
    name = name[index+1..$];
    if (extraAt)
    {
        index = name.indexOf('@');
        name = name[index+1..$];
    }

}

string Undecorate(string name)
{
    if (name[0] != '?') return name;

    if (name.startsWith("??_C@"))
    {
        return UndecorateConstantString(name);
    }
    else
    {
        wchar[1024] undname;
        dbghlp.UnDecorateSymbolNameW(name.toUTF16z(), &undname, undname.length, 0);
        return FromCStr(cast(wchar*)undname);
    }
}

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
        foreach (ref s; syms)
        {
            s.name = Undecorate(s.name);
        }
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
        SymInfo sym;
        sym.name = FromCStr(cast(wchar*)info.Name);
        sym.tag = info.Tag;
        sym.len = len > 0 ? len : info.Size;
        sym.srcline = 0;

        IMAGEHLP_LINEW64 line;
		line.SizeOfStruct = line.sizeof;
		DWORD dis;
		BOOL ret = dbghlp.SymGetLineFromAddrW64(process_handle, info.Address, &dis, &line);
		if (ret)
		{
			sym.srcfile = FromCStr(line.FileName);
			sym.srcline = line.LineNumber;
		}
		else
		{
			sym.srcfile = "no_source_info";
		}

        SymEnumContext* context = cast(SymEnumContext*)param;
        sym.addr = info.Address - context.baseAddress;
        context.symCount++;
        context.syms ~= sym;

        // TODO: update progress here

        return TRUE;
    }
}

