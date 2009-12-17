#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_securid

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/securid/core/eap_type_securid_client.cpp \
	$(WLAN_COMMON)/type/securid/core/eap_type_securid.cpp \
	$(WLAN_COMMON)/type/securid/core/eap_type_securid_server.cpp \
	$(WLAN_COMMON)/type/securid/core/eap_type_securid_state.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_securid_simulator.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
