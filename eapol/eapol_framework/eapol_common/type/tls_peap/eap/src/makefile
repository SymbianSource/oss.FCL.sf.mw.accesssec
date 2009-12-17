#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_tls_peap

SRC_FILES_CPP = $(WLAN_COMMON)/type/tls_peap/eap/src/eap_type_tls_peap.cpp \
				$(WLAN_COMMON)/type/tls_peap/eap/src/eap_type_tls_peap_state_notification.cpp \
				$(WLAN_COMMON)/type/tls_peap/eap/src/eap_type_tls_peap_header.cpp

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_peap.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_tools.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	-lstdc++

ifdef USE_MSCHAPV2_EAP_TYPE
# This is needed for EAP-TTLS/plain MsChapv2.
LIBS := ${LIBS} \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_mschapv2.$(LIB)
endif

include $(WLAN_LINUX)/base.mak

# end
