#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_simple_config

SRC_FILES_CPP = $(WLAN_COMMON)/type/simple_config/eap/src/eap_type_simple_config.cpp \
				$(WLAN_COMMON)/type/simple_config/eap/src/eap_type_simple_config_state_notification.cpp \
				$(WLAN_COMMON)/type/simple_config/eap/src/eap_type_simple_config_header.cpp

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_simple_config.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
