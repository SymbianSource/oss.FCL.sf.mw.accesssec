#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_peap

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_application_eap_core.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_application_ttls_plain_mschapv2.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_completion.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_record.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_base_record.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_base_application.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_record_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_handshake_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_alert_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_application_data_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_change_cipher_spec_message.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_peap_tlv_payloads.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_handshake_header.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_peap_tlv_header.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_record_header.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_extension.cpp \
	$(WLAN_COMMON)/type/tls_peap/tls/src/tls_peap_types.cpp \
	$(WLAN_COMMON)/type/diameter/src/eap_diameter_avp_header.cpp \
	$(WLAN_COMMON)/type/diameter/src/eap_diameter_payloads.cpp \
	$(WLAN_COMMON)/type/diameter/src/eap_diameter_avp_code.cpp

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_tools.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_tls_peap_simulator.$(LIB) \
	-lstdc++

ifdef USE_MSCHAPV2_EAP_TYPE
# This is needed for EAP-TTLS/plain MsChapv2.
LIBS := ${LIBS} \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_mschapv2.$(LIB)
endif

include $(WLAN_LINUX)/base.mak

# end
