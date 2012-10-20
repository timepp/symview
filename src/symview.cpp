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
	wprintf(L"\r已处理符号数:%d", count);
}

void OutputResult(const symlist_t& lst, const wchar_t* path)
{
	OPBLOCK(L"保存结果");

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

	SET_LONG_OP(L"排序");
	std::sort(syms.begin(), syms.end(), &inner::sort_by_addr);

	SETOP(L"打开文件");
	FILE* fp = _wfopen(path, L"wt");
	tp::throw_stderr_when(fp == NULL);

	SET_LONG_OP(L"写入文件");
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

	SETOP(L"关闭文件");
	if (fp != stdout)
	{
		fclose(fp);
		wprintf(L"已生成文件：%s\n", path);
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
	OPBLOCK(std::wstring(tp::cz(L"处理PDB文件[%s]", pdbfile.c_str())));
	wprintf(L"处理文件[%s]\n", pdbfile.c_str());

	DWORD len = 0;

	SETOP(L"打开文件");
	HANDLE file = ::CreateFileW(pdbfile.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	tp::throw_winerr_when(file == INVALID_HANDLE_VALUE);

	SETOP(L"读取文件长度");
	len = ::GetFileSize(file, NULL);


	SETOP(L"加载PDB文件");
	DWORD64 base = ::SymLoadModule64(hProcess, file, const_cast<char*>((const char *)tp::w2a(pdbfile.c_str())), NULL, 0x10000000, len);
	ENSURE(base > 0);

	SETOP(L"获取PDB信息");
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

	SETOP(L"遍历PDB文件中的符号");
	ENSURE(::SymEnumSymbolsW(hProcess, base, g_matcher.c_str(), callback, &context));

	SETOP(L"卸载PDB文件");
	ENSURE(::SymUnloadModule64(hProcess, base));

	SETOP(L"关闭PDB文件");
	::CloseHandle(file);

	UpdateSymCountDisplay(context.symCount);
	wprintf(L"\n");
}

void print_help(const wchar_t* progname, tp::cmdline_parser& parser)
{
	wprintf(
		L"%s: 通过分析PDB显示EXE/DLL中函数和变量的大小信息。\n"
		L"用法: %s PDBFile\n"
		L"\n"
		L"输出<PDBFile>.csv文件，每一行代表一个函数/全局变量的属性，逗号分隔，字段含意依次为：\n"
		L"　　类型(函数还是全局变量)\n"
		L"　　地址\n"
		L"　　大小（字节）\n"
		L"　　实际占用大小（字节）\n"
		L"　　名字\n"
		L"　　源代码文件\n"
		L"　　源代码行号\n"
		L"输出按地址从小到大排序\n"
		L"\n"
		L"举例：\n"
		L"codesize bdcommon.pdb\n"
		L"以上命令分析bdcommon.pdb，生成bdcommon.pdb.csv文件.\n",
		progname, progname
	);
}

const wchar_t* getname(const wchar_t* path)
{
	const wchar_t* p = wcsrchr(path, L'\\');
	return p? p+1 : path;
}

int main_internal(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");

	hProcess = ::GetCurrentProcess();
	SETOP(L"解析命令行");

	tp::cmdline_parser parser;
	parser.register_string_option(L"m", L"matcher", &g_matcher);

	try
	{
		parser.parse(argc, argv);
		tp::throw_when(parser.get_target_count() < 1, L"");
	}
	catch (tp::exception& e)
	{
		wprintf(L"%s\n\n", e.message.c_str());
		print_help(getname(argv[0]), parser);
		return 1;
	}

	SETOP(L"初始化符号环境");
	ENSURE(::SymInitialize(hProcess, NULL, FALSE));
	DWORD opt = ::SymSetOptions(SYMOPT_LOAD_LINES);
	//::SymSetOptions(::SymGetOptions() | SYMOPT_LOAD_LINES);

	for (size_t i = 0; i < parser.get_target_count(); i++)
	{
		try
		{
			std::wstring pdbfile = parser.get_target(i);
			std::wstring outfile = pdbfile + L".csv";
			symlist_t lst;
			EnumPdbSymbol(pdbfile, EnumProc, &lst);
			OutputResult(lst, outfile.c_str());
		}
		catch (tp::exception& e)
		{
			wprintf(L"错误: %s\n当前操作: %s\n", e.message.c_str(), e.oplist.c_str());
		}
	}

	SETOP(L"退出符号环境");
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
		wprintf(L"错误: %s\n当前操作: %s\n", e.message.c_str(), e.oplist.c_str());
		return -1;
	}

	return 0;
}

