#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_aka_tools

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_payloads.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_authentication_vector.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_header.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_testing_tools.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
