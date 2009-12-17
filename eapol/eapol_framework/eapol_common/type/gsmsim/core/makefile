#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_gsmsim

SRC_FILES_CPP = \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_client.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_payloads.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_server.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_state.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_state_notification.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_header.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_initialized.cpp \
	$(WLAN_COMMON)/type/gsmsim/core/eap_type_gsmsim_mac_attributes.cpp

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_gsmsim_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_testing_tools.$(LIB) \
	-lstdc++

#	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_dummy_sim.$(LIB) \

include $(WLAN_LINUX)/base.mak

# end
