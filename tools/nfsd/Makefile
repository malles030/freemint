#
# Makefile for the NFS server: portmap, mountd and nfsd
#

SHELL = /bin/sh
SUBDIRS =

srcdir = .
top_srcdir = ..
subdir = nfsd

default: help

include $(top_srcdir)/CONFIGVARS
include $(top_srcdir)/RULES
include $(top_srcdir)/PHONY

include $(srcdir)/NFSDDEFS
include $(srcdir)/SRCFILES

all-here: all-targets

# default definitions
compile_all_dirs = .compile_*
GENFILES = $(compile_all_dirs)

help:
	@echo '#'
	@echo '# targets:'
	@echo '# --------'
	@echo '# - all'
	@echo '# - $(alltargets)'
	@echo '#'
	@echo '# - clean'
	@echo '# - distclean'
	@echo '# - bakclean'
	@echo '# - strip'
	@echo '# - check     (host side tests, needs a host compiler)'
	@echo '# - help'
	@echo '#'

EXES = portmap mountd nfsd

ALL_TARGETS = $(foreach TARGET, $(alltargets), $(foreach EXE, $(EXES), .compile_$(TARGET)/$(EXE)))

strip:
	$(STRIP) $(ALL_TARGETS)

all-targets: $(ALL_TARGETS)

#
# MiNT has fsync(), and statvfs() only in newer MiNTLibs. FSSTAT answers
# zeroes without it, which a client displays as an unknown size rather than
# failing, so it stays optional.
#
DEFINITIONS = -DHAVE_FSYNC

#
# Host side tests.
#
# These build with the host compiler, not the cross compiler: two of them
# are unit tests of code that is platform independent, and the other three
# drive the daemons over a socket. Running them before a change goes to the
# Atari is much faster than finding out there.
#
HOSTCC = cc
HOSTCFLAGS = -Wall -Wextra -O1

check:
	@echo "--- xdr core ---"
	@$(HOSTCC) $(HOSTCFLAGS) -o /tmp/nfsd_t_xdr $(srcdir)/t_xdr.c $(srcdir)/xdr.c
	@/tmp/nfsd_t_xdr
	@echo "--- file handles ---"
	@$(HOSTCC) $(HOSTCFLAGS) -o /tmp/nfsd_t_fh $(srcdir)/t_fh.c $(srcdir)/fh.c
	@/tmp/nfsd_t_fh
	@echo
	@echo "The three protocol tests need the daemons running; see README."

#
# multi target stuff
#

define TARGET_TEMPLATE

$(1):: .compile_$(1)/$(2)

LIBS_$(1) =
OBJS_$(2)_$(1) = $(foreach OBJ, $(notdir $(basename $(OBJS_$(2)))), .compile_$(1)/$(OBJ).o)
DEFINITIONS_$(1) = $(DEFINITIONS)

.compile_$(1)/$(2): $$(OBJS_$(2)_$(1))
	$(LD) $$(LDEXTRA_$(1)) -o $$@ $$(CFLAGS_$$(CPU_$(1))) $$(OBJS_$(2)_$(1)) $$(LIBS_$(1))

endef

$(foreach TARGET,$(alltargets), $(foreach EXE, $(EXES), $(eval $(call TARGET_TEMPLATE,$(TARGET),$(EXE)))))

$(foreach TARGET,$(alltargets),$(foreach OBJ,$(COBJS),$(eval $(call CC_TEMPLATE,$(TARGET),$(OBJ)))))

#
# The dependency files live in .compile_<target>/.deps, and the rules above
# write into those directories without creating them first. Same line as in
# tools/fdisk and the other tools in this tree.
#
ifneq (clean,$(findstring clean,$(MAKECMDGOALS)))
DEPS_MAGIC := $(shell mkdir -p $(addsuffix /.deps,$(addprefix .compile_,$(alltargets))) > /dev/null 2>&1 || :)
endif
