SRCS=imgact_mach.c vnode_if.h
KMOD=imgact_mach

PWD != pwd
CFLAGS += -DDYLD=\"$(PWD)/loader\"

.include <bsd.kmod.mk>

