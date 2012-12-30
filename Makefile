CPP = cl
CPPFLAGS = /c /nologo /Ithirdsrc /DWIN32 /MT /Zi

LD = link
LDFLAGS = /DEBUG /NODEFAULTLIB:libc

all: symview.exe

symview.exe: symview.o

{src\}.cpp.o::
	$(CPP) $(CPPFLAGS) $<


clean :
	-del /f symview.exe
	-del /f *.obj
	-del /f *.pdb
	-del /f *.idb
	-del /f *.ilk
