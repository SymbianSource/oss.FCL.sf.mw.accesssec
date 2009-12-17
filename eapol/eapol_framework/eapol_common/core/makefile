#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core

SRC_FILES_CPP = \
	$(WLAN_COMMON)/core/eap_core.cpp \
	$(WLAN_COMMON)/core/eapol_core.cpp \
	$(WLAN_COMMON)/core/ethernet_core.cpp \
	$(WLAN_COMMON)/core/eap_core_nak_info.cpp \
	$(WLAN_COMMON)/core/eap_core_retransmission.cpp \
	$(WLAN_COMMON)/core/eapol_key_state_common.cpp \
	$(WLAN_COMMON)/core/eapol_key_state_client.cpp \
	$(WLAN_COMMON)/core/eapol_key_state_server.cpp \
	$(WLAN_COMMON)/core/eapol_key_state_string.cpp \
	$(WLAN_COMMON)/core/eapol_rsna_key_data_payloads.cpp \
	$(WLAN_COMMON)/core/eapol_rc4_key_header.cpp \
	$(WLAN_COMMON)/core/eapol_rsna_key_data_header.cpp \
	$(WLAN_COMMON)/core/eapol_rsna_key_data_gtk_header.cpp \
	$(WLAN_COMMON)/core/eapol_rsna_key_header.cpp \
	$(WLAN_COMMON)/core/eap_type_selection.cpp \

ifndef NO_EAP_SESSION_CORE
SRC_FILES_CPP := $(SRC_FILES_CPP) \
	$(WLAN_COMMON)/core/eap_session_core.cpp
endif

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \

include $(WLAN_LINUX)/base.mak

# end
