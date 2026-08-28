# Optimisation levels, the single place they are defined.
#
# Both configure.ac and scripts/build-static.sh source this file, so a change
# here applies everywhere; do not spread -O levels across Makefile.am files.
#
# Components are graded by where they sit on the data path:
#
#   CRYPTO  runs per byte. -O2 is the same code size as -Os but noticeably
#           faster, and -O3 buys a little more for a few kilobytes.
#   HOT     runs once per event or packet: the relay itself and libev.
#   COLD    runs at most once per connection: pcre for ACL matching and
#           c-ares for name resolution. Size traded for nothing there.
#
# libcork, libipset and libbloom are submodules without their own AM_CFLAGS,
# so they follow the global CFLAGS (HOT); not worth patching them for size.

SS_OPT_CRYPTO="-O3"
SS_OPT_HOT="-O2"
SS_OPT_COLD="-Os"

# Flags shared by every component, unrelated to the optimisation level.
#
# -ffunction-sections and -fdata-sections must be set at compile time or the
# linker's --gc-sections has nothing to work with inside a library.
#
# -fno-asynchronous-unwind-tables drops .eh_frame. Nothing here unwinds the
# stack, so it only costs a backtrace on a crash, which a stripped release
# binary cannot produce anyway.
SS_CFLAGS_COMMON="-fno-pie -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables"
