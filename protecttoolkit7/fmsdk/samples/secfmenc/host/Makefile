all: secfmenctest

ifneq ($(EMUL),$(NULL))
include $(FMDIR)/cfgbuild.mak
FM_PATH:=..$(PS)fm
endif

CFLAGS=-I$(CPROVDIR)/include -I../include -fPIC -DLINUX -DIS_LITTLE_ENDIAN -Wall -Werror -Wno-unused-but-set-variable
ifneq ($(EMUL), $(NULL))
	LDFLAGS = -L$(FM_PATH)$(PS)$(OBJDIR) -Wl,-rpath $(FM_PATH)$(PS)$(OBJDIR)
else
	LDFLAGS=-L$(CPROVDIR)/lib
endif

secfmenctest: secfmenctest.o
	$(CC) $(LDFLAGS) -o secfmenctest secfmenctest.o -lcryptoki

clean:
	-rm secfmenctest.o secfmenctest
