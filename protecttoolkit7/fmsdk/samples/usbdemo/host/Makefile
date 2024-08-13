# Copyright (c) 2018 SafeNet Inc.

all: build
CONSOLE:=1

ifneq ($(EMUL),$(NULL))

build:

clean:

else

include $(FMDIR)/cfgbuild.mak

CFLAGS+=-I . -I../include/. -I$(FMDIR)/include -g

ifeq ($(OS),Windows_NT)
   ifneq ($(DEBUG),$(NULL))
      CFLAGS+= /MDd
   else
      CFLAGS+= /MD
   endif
   LFLAGS += /LIBPATH:../host/$(OBJDIR)
	LFLAGS+=/LIBPATH:$(LIBDIR)
else
    LFLAGS += -L../host/$(OBJDIR)
endif

NAME:=usbhost
LIBS+=util ethsm


build: $(ARCH_EXE)

OBJS:=\
	$(NAME)

$(ARCH_EXE): $(OBJDIR) $(ARCH_OBJS)
	gcc -g -c $(CFLAGS) $(NAME).c
	$(LN) -g $(OUT)$(ARCH_EXE) $(LFLAGS) $(ARCH_OBJS) $(ARCH_LIBS)

clean :
	echo ARCH_CLEAN=$(ARCH_CLEAN)
	-$(RM) $(ARCH_CLEAN)
# Do not remove entire directory!	
#	-$(RMDIR) $(subst /,$(PS),$(OBJDIR))

endif
