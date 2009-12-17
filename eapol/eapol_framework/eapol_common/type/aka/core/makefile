#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_aka

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_authentication_vector.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_client.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_header.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_payloads.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_server.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_state.cpp \
	$(WLAN_COMMON)/type/aka/core/eap_type_aka_state_notification.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_aka_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_testing_tools.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_aka_tools.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
