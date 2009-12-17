#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_mschapv2

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/mschapv2/core/eap_type_mschapv2.cpp \
	$(WLAN_COMMON)/type/mschapv2/core/eap_type_mschapv2_client.cpp \
	$(WLAN_COMMON)/type/mschapv2/core/eap_type_mschapv2_credential_store.cpp \
	$(WLAN_COMMON)/type/mschapv2/core/eap_type_mschapv2_header.cpp \
	$(WLAN_COMMON)/type/mschapv2/core/eap_type_mschapv2_server.cpp \
	$(WLAN_COMMON)/type/mschapv2/core/eap_type_mschapv2_state.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_mschapv2_simulator.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
