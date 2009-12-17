#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_tools

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_peap_types.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
