#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_simple_config_tools

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/simple_config/simple_config/src/simple_config_payloads.cpp \
	$(WLAN_COMMON)/type/simple_config/simple_config/src/simple_config_tlv_header.cpp \
	$(WLAN_COMMON)/type/simple_config/simple_config/src/simple_config_credential.cpp \
	$(WLAN_COMMON)/type/simple_config/simple_config/src/simple_config_message.cpp \
	$(WLAN_COMMON)/type/simple_config/simple_config/src/simple_config_types.cpp \
	$(WLAN_COMMON)/core/eapol_rsna_key_header.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
