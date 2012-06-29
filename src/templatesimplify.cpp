#include "stdafx.h"
#include "templatesimplify.h"
#include <regex>

struct
{
	std::wregex* reg;
	std::wstring rep;
} g_replacer[] =
{
	{
		new std::wregex(L"CStringT<wchar_t,ATL::StrTraitATL<wchar_t,ATL::ChTraitsCRT<wchar_t> > >"),
		L"CStringW"
	},
	{
		new std::wregex(L"CStringT<char,ATL::StrTraitATL<char,ATL::ChTraitsCRT<char> > >"),
		L"CStringA"
	},
	{
		new std::wregex(L"basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t> >"),
		L"wstring"
	},
	{
		new std::wregex(L"<(.+),std::allocator<\\1 *> *>"),
		L"<$1>"
	},
	{
		new std::wregex(L"map\\<(.+),(.+),std::less<\\1 *>,std::allocator<std::pair<\\1 ?const ?,\\2 *> *> *>"),
		L"map<$1,$2>"
	},
	{
		new std::wregex(L"(_Tree|_Tree_nod)<std::_Tmap_traits<(.+),(.+),std::less<\\2 *>,std::allocator<std::pair<\\2 ?const ?,\\3 *> *>,0> *>"),
		L"map$1<$2,$3>"
	},
	{
		new std::wregex(L"(_Tree|_Tree_nod)<std::_Tset_traits<(.+),std::less<\\2 *>,std::allocator<\\2 *>,0 *> *>"),
		L"set$1<$2,$3>"
	},
	{
		new std::wregex(L"stack<(.+),std::deque<\\1,std::allocator<\\1 *> *> *>"),
		L"stack<$1>"
	},
	{
		new std::wregex(L"_Hash<stdext::_Hmap_traits<(.+),(.+),(.+),std::allocator<std::pair<\\1 ?const ?,\\2 *> *>,0>"),
		L"hashmap<$1,$2,$3>"
	},
};

CTemplateSimplifier::CTemplateSimplifier()
{
}

std::wstring CTemplateSimplifier::Simplify(const wchar_t* name)
{
	std::wstring ret = name;
	for (size_t i = 0; i < _countof(g_replacer); i++)
	{
		ret = std::regex_replace(ret.c_str(), *g_replacer[i].reg, g_replacer[i].rep);
	}

	return ret;
}

