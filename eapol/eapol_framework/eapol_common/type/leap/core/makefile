#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_leap

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_client.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_credential_store.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_header.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_rogue_ap_entry.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_rogue_ap_list.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_server.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_state_client.cpp \
	$(WLAN_COMMON)/type/leap/core/eap_type_leap_state_server.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_leap_simulator.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
