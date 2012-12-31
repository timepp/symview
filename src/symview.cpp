// symview.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <tplib/include/exception.h>
#include <tplib/include/tplib.h>
#include <tplib/include/cmdlineparser.h>
#include <algorithm>
#include <vector>
#include <map>
#include <Windows.h>
#include <DbgHelp.h>
#include <numeric>
#include "templatesimplify.h"

#include <time.h>

#undef max
#undef min

#define charcount(str) (_countof(str)-1)

struct syminfo
{
	std::wstring name;
	std::wstring file;
	UINT64 addr;
	int line;
	size_t len;
	ULONG tag;
};

typedef std::vector<syminfo> symlist_t;

HANDLE hProcess = ::GetCurrentProcess();
bool g_get_file_and_line = true;
std::wstring g_matcher;
int g_hide_len = -1;
CTemplateSimplifier g_ts;

#define ENSURE(cond) tp::throw_winerr_when(!(cond))

struct CSV_Safe_String : public tp::format_shim<wchar_t, 4096>
{
	explicit CSV_Safe_String(const wchar_t* str)
	{
		wchar_t* p = m_buf;
		*p++ = L'\"';
		*p++ = L' ';
		while (*str)
		{
			*p++ = *str;
			if (*str == L'\"') *p++ = *str;
			str++;
		}
		*p++ = L'\"';
		*p = L'\0';
	}
};


struct SymEnumContext
{
	symlist_t* list;
	DWORD fileSize;
	DWORD64 baseAddress;
	time_t lastProgressTime;
	int symCount;
};

static std::wstring GetDir(const std::wstring& path)
{
	size_t index = path.find_last_of(L'\\');
	if (index != std::wstring::npos)
	{
		return path.substr(0, index);
	}
	return L"";
}

bool RemoveSubStr(std::string& dest, const std::string& sub)
{
	size_t pos = dest.find(sub);
	if (pos != std::string::npos)
	{
		dest.erase(pos, sub.length());
		return true;
	}
	return false;
}

const char* GetSymType(const syminfo& s)
{
	static char buffer[20];
	switch (s.tag)
	{
	case 5: return "Function";
	case 7: return "Data";
	case 10: return "PublicSymbol";
	case 10000: return "String";
	}

	_snprintf_s(buffer, _TRUNCATE, "%u", s.tag);
	return buffer;
}

void UpdateSymCountDisplay(int count)
{
	wprintf(L"\rprocessed symbols:%d", count);
}

void OutputResult(const symlist_t& lst, const wchar_t* path)
{
	OPBLOCK(L"save result");

	symlist_t syms = lst;
	struct inner
	{
		static bool sort_by_len(const syminfo& s1, const syminfo& s2)
		{
			return 
				s1.len < s2.len ||
				s1.len == s2.len && s1.name < s2.name;
		}
		static bool sort_by_addr(const syminfo& s1, const syminfo& s2)
		{
			return s1.addr < s2.addr ||
				s1.addr == s2.addr && s1.len < s2.len;
		}
	};

	SET_LONG_OP(L"sort");
	std::sort(syms.begin(), syms.end(), &inner::sort_by_addr);

	SETOP(L"open result file");
	FILE* fp = _wfopen(path, L"wt");
	tp::throw_stderr_when(fp == NULL);

	SET_LONG_OP(L"write result file");
	fprintf_s(fp, "SymbolType,Address,Length,Occupied,SymbolName,SourceFile,SourceLine\n"); 
	for (symlist_t::const_iterator it = syms.begin(); it != syms.end(); ++it)
	{
		if (g_hide_len >= 0 && it->len <= g_hide_len) continue;

		const char* symtype = GetSymType(*it);
		int occupied = it->len;
		symlist_t::const_iterator it2 = it+1;
		if (it2 != syms.end())
		{
			occupied = it2->addr - it->addr;
			if (it2->addr % 0x1000 == 0 && occupied > it->len * 2)
			{
				occupied = it->len;
			}
		}

		int len = it->len;
		if (occupied == 0)
		{
			len = 0;
		}

		if (len > 0 && occupied > 32 && occupied > len * 2)
		{
			occupied = len;
		}

		fprintf_s(fp, "%s,=\"%I64X\",%d,%d,%S,\"%S\",%d\n", 
			symtype, it->addr, len, occupied, (const wchar_t*)CSV_Safe_String(it->name.c_str()), it->file.c_str(), it->line);
	}

	SETOP(L"close result file");
	if (fp != stdout)
	{
		fclose(fp);
		wprintf(L"result are saved to file: %s\n", path);
	}
}

const wchar_t* ExtractByte(const wchar_t* p, int* val)
{
	if (!p || *p == L'@')
	{
		return NULL;
	}

	if (*p != L'?')
	{
		*val = *p;
		return p+1;
	}
	else
	{
		p++;
		if (*p >= L'a' && *p <= L'z')
		{
			*val = 0xe1 + *p - L'a';
			return p+1;
		}
		if (*p >= L'A' && *p <= L'Z')
		{
			*val = 0xc1 + *p - L'A';
			return p+1;
		}
		if (*p == L'$')
		{
			*val = (p[1] - L'A') * 16 + (p[2] - L'A');
			return p+3;
		}

		// 特殊符号
		switch (*p)
		{
		case L'0': *val = L',';break;
		case L'1': *val = L'/';break;
		case L'2': *val = L'\\';break;
		case L'3': *val = L':';break;
		case L'4': *val = L'.';break;
		case L'5': *val = L' ';break;
		case L'6': *val = 0x0a;break;
		case L'7': *val = 0x09;break;
		case L'8': *val = L'\'';break;
		case L'9': *val = L'-';break;
		}
		return p+1;
	}
}

wchar_t* EncodeChar(wchar_t ch, wchar_t (&buf)[16])
{
	wchar_t* p = buf;

	// 特殊符号
	switch (ch)
	{
	case L'\t': return L"\\t";
	case L'\n': return L"\\n";
	case L'\r': return L"\\r";
	case L'\\': return L"\\\\";
	default: break;
	}

	if (ch > 0 && ch < 0x20 || ch > 0x7F && ch <= 0xFF)
	{
		_snwprintf_s(buf, _TRUNCATE, L"\\x%02X", ch);
	}
	else
	{
		buf[0] = ch;
		buf[1] = L'\0';
	}

	return buf;
}

std::wstring UnDecorateString(const wchar_t* name)
{
	std::wstring ret;

	name += 6;
	bool ansi = (*name == L'0');  // *name==0 : ansi, *name==1 : unicode

	// 接下来是长度字段,我们跳过. 直接定位到真正的字符串开始
	// 不过如果长度字段不是'0'~'9',会有一个额外的@标示长度字段结束
	const wchar_t* p = wcschr(name, L'@');
	if (name[1] < L'0' || name[1] > L'9')
	{
		p = wcschr(p+1, L'@');
	}
	p++;

	// 真正的内容啦
	wchar_t buf[16];
	int t;
	if (ansi)
	{
		const wchar_t* q = p;
		while (q && *q != L'@')
		{
			q = ExtractByte(q, &t);
			ret += EncodeChar(t, buf);
		}
	}
	else
	{
		const wchar_t*q = p;
		while (q && *q != L'@')
		{
			int wt;
			q = ExtractByte(q, &t);
			wt = t << 8;
			q = ExtractByte(q, &t);
			wt += t;
			ret += EncodeChar(wt, buf);
		}
	}

	return ret;
}

BOOL CALLBACK EnumProc(PSYMBOL_INFOW info, ULONG len, PVOID param)
{
	SymEnumContext* context = (SymEnumContext*)param;

	syminfo sym;
	sym.tag = info->Tag;
	sym.len = len > 0? len : info->Size;
	sym.addr = info->Address - context->baseAddress;
	sym.line = 0;

	wchar_t buffer1[4096];
	wchar_t buffer2[4096];

	// undecorate
	std::wstring undstr;
	const wchar_t* undecorateName = info->Name;
	if (*undecorateName == L'?')
	{
		if (wcsncmp(undecorateName, L"??_C@", 5) == 0)
		{
			// UndecorateSymbolName不管STRING,所以我们只好自己解析
			undstr = UnDecorateString(info->Name);
			undecorateName = undstr.c_str();
			sym.tag = 10000;
		}
		else
		{
			::UnDecorateSymbolNameW(info->Name, buffer1, _countof(buffer1), 0);
			undecorateName = buffer1;
		}
	}

	// simplify
	if (wcschr(undecorateName, L'<'))
	{
		sym.name = g_ts.Simplify(undecorateName);
	}
	else
	{
		sym.name = undecorateName;
	}
	
	if (g_get_file_and_line)
	{
		IMAGEHLP_LINEW64 line;
		line.SizeOfStruct = sizeof(line);
		DWORD dis;
		BOOL ret = ::SymGetLineFromAddrW64(hProcess, info->Address, &dis, &line);
		if (ret)
		{
			sym.file = line.FileName;
			sym.line = line.LineNumber;
		}
		else
		{
			sym.file = L"no_source_info";
		}
	}

	context->list->push_back(sym);

	context->symCount++;
	time_t currTime = time(NULL);
	if (context->lastProgressTime != currTime)
	{
		context->lastProgressTime = currTime;
		UpdateSymCountDisplay(context->symCount);
	}

	return TRUE;
}

void EnumPdbSymbol(std::wstring& pdbfile, PSYM_ENUMERATESYMBOLS_CALLBACKW callback, symlist_t* list)
{
	OPBLOCK(std::wstring(tp::cz(L"process file [%s]", pdbfile.c_str())));
	wprintf(L"process file[%s]\n", pdbfile.c_str());

	::SymSetSearchPathW(::GetCurrentProcess(), GetDir(pdbfile).c_str());

	DWORD len = 0;

	SETOP(L"open file");
	HANDLE file = ::CreateFileW(pdbfile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	tp::throw_winerr_when(file == INVALID_HANDLE_VALUE);

	SETOP(L"read file length");
	len = ::GetFileSize(file, NULL);


	SETOP(L"load file");
	DWORD64 base = ::SymLoadModule64(GetCurrentProcess(), file, NULL, NULL, 0x10000000, len);
	ENSURE(base > 0);

	SETOP(L"get symbol information");
	IMAGEHLP_MODULE64 ModuleInfo; 
	memset(&ModuleInfo, 0, sizeof(ModuleInfo) ); 
	ModuleInfo.SizeOfStruct = sizeof(ModuleInfo); 
	BOOL bRet = ::SymGetModuleInfo64( GetCurrentProcess(), base, &ModuleInfo ); 

	SymEnumContext context;
	context.list = list;
	context.baseAddress = base;
	context.fileSize = len;
	context.symCount = 0;
	list->reserve(100000);

	SETOP(L"enum symbols");
	ENSURE(::SymEnumSymbolsW(hProcess, base, NULL, callback, &context));

	SETOP(L"unload file");
	ENSURE(::SymUnloadModule64(hProcess, base));

	SETOP(L"close file");
	::CloseHandle(file);

	UpdateSymCountDisplay(context.symCount);
	wprintf(L"\n");
}

void print_help(const wchar_t* progname, tp::cmdline_parser& parser)
{
	wprintf(
		L"symview: view symbols in EXE or DLL. \n"
		L"usage: symview <file>(exe,dll,...)\n"
		L"generates <file>.symbols.csv, in CSV compitable format. \n"
		L"each line represents a symbol, fields(symbol properties) are separates by `,', including:\n"
		L"  symbol type\n"
		L"  address(offset in the binary)\n"
		L"  length in bytes\n"
		L"  occupy in bytes\n"
		L"  name\n"
		L"  source file\n"
		L"  source line\n"
		L"symbols are sorted by their addresses.\n"
		L"note: corresponding pdb files must exists in the some direcotry.\n"
		L"example:\n"
		L"symview bdcommon.dll\n"
		L"this command analyze `bdcommon.dll' and `bdcommon.pdb', then generates result in `bdcommon.dll.symbols.csv'\n"
		L"\n"
		L"visit: https://github.com/timepp/symview \n"
	);
}

const wchar_t* getname(const wchar_t* path)
{
	const wchar_t* p = wcsrchr(path, L'\\');
	return p? p+1 : path;
}

int main_internal(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "chs");

	hProcess = ::GetCurrentProcess();
	SETOP(L"parse command line");

	tp::cmdline_parser parser;
	parser.register_string_option(L"m", L"matcher", &g_matcher);

	try
	{
		parser.parse(argc, argv);
		tp::throw_when(parser.get_target_count() < 1, L"");
	}
	catch (tp::exception& e)
	{
		if (e.message.length())
			wprintf(L"%s\n\n", e.message.c_str());
		print_help(getname(argv[0]), parser);
		return 1;
	}

	SETOP(L"init symbol service");
	ENSURE(::SymInitialize(hProcess, NULL, FALSE));
	DWORD opt = ::SymGetOptions();
	::SymSetOptions(0 | SYMOPT_LOAD_LINES);

	for (size_t i = 0; i < parser.get_target_count(); i++)
	{
		try
		{
			std::wstring pdbfile = parser.get_target(i);
			std::wstring outfile = pdbfile + L".symbols.csv";
			symlist_t lst;
			EnumPdbSymbol(pdbfile, EnumProc, &lst);
			OutputResult(lst, outfile.c_str());
		}
		catch (tp::exception& e)
		{
			wprintf(L"error: %s\ncurrent operation: %s\n", e.message.c_str(), e.oplist.c_str());
		}
	}

	SETOP(L"uninit symbol service");
	ENSURE(::SymCleanup(hProcess));

	return 0;
}

int wmain(int argc, wchar_t* argv[])
{
	try
	{
		return main_internal(argc, argv);
	}
	catch (tp::exception& e)
	{
		wprintf(L"error: %s\ncurrent operation: %s\n", e.message.c_str(), e.oplist.c_str());
		::Sleep(10000);
		return -1; 
	}

	return 0;
}

