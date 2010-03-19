#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_wapi

ifdef USE_WAPI_CORE
SRC_FILES_CPP = \
	$(WAPI_COMMON)/src/ec_cs_data.cpp \
	$(WAPI_COMMON)/src/ec_cs_strings.cpp \
	$(WAPI_COMMON)/src/ec_cs_tlv.cpp \
	$(WAPI_COMMON)/src/ec_cs_tlv_header.cpp \
	$(WAPI_COMMON)/src/ec_cs_tlv_message.cpp \
	$(WAPI_COMMON)/src/ec_cs_tlv_payloads.cpp \
	$(WAPI_COMMON)/src/wai_message.cpp \
	$(WAPI_COMMON)/src/wai_message_payloads.cpp \
	$(WAPI_COMMON)/src/wai_protocol_packet_header.cpp \
	$(WAPI_COMMON)/src/wai_tlv_header.cpp \
	$(WAPI_COMMON)/src/wai_usksa.cpp \
	$(WAPI_COMMON)/src/wai_variable_data.cpp \
	$(WAPI_COMMON)/src/wapi_core.cpp \
	$(WAPI_COMMON)/src/wapi_strings.cpp \
	$(WAPI_COMMON)/src/wapi_core_retransmission.cpp \

#	$(WAPI_COMMON)/src/wapi_message_wlan_authentication.cpp \
#	$(WAPI_COMMON)/src/wapi_wlan_authentication.cpp \

SRC_FILES_C = 

endif


LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_tools.$(LIB) \
	-lstdc++

include $(WLAN_LINUX)/base.mak

# end
