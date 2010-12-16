#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_peap_wpx

SRC_FILES_C = 
SRC_FILES_CPP =

ifdef USE_FAST_EAP_TYPE
SRC_FILES_CPP := $(SRC_FILES_CPP) \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/tls_application_eap_fast.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_tlv_payloads.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_tlv_header.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_tlv_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_pac_tlv.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_pac_store.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_strings.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_pac_store_types.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_pac_file_data_header.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/wpx/eap_fast_pac_store_completion.cpp
endif

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_tools.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
