#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_all

SRC_FILES_CPP = $(WLAN_COMMON)/type/eap_type_all.cpp \

SRC_FILES_C = 

LIBS = $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_core.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_gsmsim.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_peap.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_tls_peap.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_gsmsim_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_tls_peap_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_simple_config.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_simple_config_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_tls_tools.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_simple_config_tools.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_aka.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_aka_simulator.$(LIB) \

ifdef USE_SAE_EAP_TYPE
LIBS := ${LIBS} \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_sim_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_dummy_sim.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_saesim_core.$(LIB)
endif

ifdef USE_MSCHAPV2_EAP_TYPE
LIBS := $(LIBS) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_type_mschapv2_simulator.$(LIB) \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_mschapv2.$(LIB)
endif

ifdef USE_SECURID_EAP_TYPE
LIBS := ${LIBS} \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_securid.$(LIB)
endif

ifdef USE_LEAP_EAP_TYPE
LIBS := ${LIBS} \
	$(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_type_leap.$(LIB)
endif

include $(WLAN_LINUX)/base.mak

# end
