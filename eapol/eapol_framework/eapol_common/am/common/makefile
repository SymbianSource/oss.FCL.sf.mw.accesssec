#.EXPORT_ALL_VARIABLES:

DLL_TARGET = do_dll

LIBRARY_NAME := $(WLAN_LINUX)/project/$(EAP_OSTYPE)/gcc_eap_am_common

SRC_FILES_CPP = \
	$(WLAN_COMMON)/common/eap_crypto_api.cpp \
	$(WLAN_COMMON)/am/common/abs_eap_am_mutex.cpp \
	$(WLAN_COMMON)/am/common/abs_eap_am_semaphore.cpp \
	$(WLAN_COMMON)/am/common/eap_am_tools.cpp \
	$(WLAN_COMMON)/am/common/eap_am_memory.cpp \
	$(WLAN_COMMON)/am/common/eap_am_network_id.cpp \
	$(WLAN_COMMON)/am/common/eap_timer_queue.cpp \
	$(WLAN_COMMON)/am/common/eap_am_memory_store.cpp \
	$(WLAN_COMMON)/am/common/eap_am_memory_store_data.cpp \
	$(WLAN_COMMON)/am/common/eap_file_config.cpp \
	$(WLAN_COMMON)/am/common/DSS_random/dss_random.cpp \
	$(WLAN_COMMON)/common/asn1_der_type.cpp \
	$(WLAN_COMMON)/common/eap_base_type.cpp \
	$(WLAN_COMMON)/common/eap_buffer.cpp \
	$(WLAN_COMMON)/common/eap_general_header_base.cpp \
	$(WLAN_COMMON)/common/eap_header.cpp \
	$(WLAN_COMMON)/common/eap_expanded_type.cpp \
	$(WLAN_COMMON)/common/eap_header_string.cpp \
	$(WLAN_COMMON)/common/eap_memory_store_variable_data.cpp \
	$(WLAN_COMMON)/common/eap_rogue_ap_entry.cpp \
	$(WLAN_COMMON)/common/eap_sim_triplets.cpp \
	$(WLAN_COMMON)/common/eap_tlv_header.cpp \
	$(WLAN_COMMON)/common/eap_tlv_message_data.cpp \
	$(WLAN_COMMON)/common/eap_tools.cpp \
	$(WLAN_COMMON)/common/eap_status_string.cpp \
	$(WLAN_COMMON)/common/eap_variable_data.cpp \
	$(WLAN_COMMON)/common/eap_master_session_key.cpp \
	$(WLAN_COMMON)/common/eap_state_notification.cpp \
	$(WLAN_COMMON)/common/eapol_session_key.cpp \
	$(WLAN_COMMON)/common/eap_network_id_selector.cpp \
	$(WLAN_COMMON)/common/eapol_ethernet_header.cpp \
	$(WLAN_COMMON)/common/eapol_header.cpp \
	$(WLAN_COMMON)/am/common/stack/eap_am_stack_trace.cpp \
	$(WLAN_TESTING)/am/common/openssl/eap_am_crypto_openssl.cpp \
	$(WLAN_COMMON)/am/common/crypto/random/eap_am_random_test.cpp \
	$(WLAN_COMMON)/am/common/crypto/sha1/eap_am_crypto_sha1.cpp \
	$(WLAN_COMMON)/am/common/crypto/md4/eap_am_crypto_md4.cpp \
	$(WLAN_COMMON)/am/common/crypto/rc4/eap_am_crypto_rc4.cpp \
	$(WLAN_COMMON)/am/common/crypto/sha1/eap_am_crypto_sha1.cpp \
	$(WLAN_COMMON)/am/common/crypto/sha-256/eap_am_crypto_sha_256.cpp \

#	$(WLAN_LINUX)/am/common/linux_gnu/eap_am_tools_linux-gnu.cpp \
#	$(WLAN_LINUX)/am/common/linux_gnu/eap_am_mutex_linux-gnu.cpp \
#	$(WLAN_LINUX)/am/common/linux_gnu/eap_am_semaphore_linux-gnu.cpp

SRC_FILES_CPP := $(SRC_FILES_CPP) \
	$(WLAN_TESTING)/am/common/file_io/stdio/eap_am_file_input_stdio.cpp \
	$(WLAN_TESTING)/am/common/file_trace/eap_am_trace_file_stdio.cpp

ifeq (linux_gnu,$(EAP_OSTYPE))
	SRC_FILES_CPP := $(SRC_FILES_CPP) \
		$(WLAN_LINUX)/am/eap_test_timer/linux_gnu/eap_test_timer.cpp \
		$(WLAN_LINUX)/am/common/linux_gnu/eap_am_tools_linux-gnu.cpp \
		$(WLAN_LINUX)/am/common/linux_gnu/eap_am_mutex_linux-gnu.cpp \
		$(WLAN_LINUX)/am/common/linux_gnu/eap_am_semaphore_linux-gnu.cpp
endif

ifeq (cygwin,$(EAP_OSTYPE))
	SRC_FILES_CPP := $(SRC_FILES_CPP) \
		$(WLAN_WINDOWS)/am/eap_test_timer/cygwin/eap_test_timer.cpp \
		$(WLAN_WINDOWS)/am/common/win32_and_cygwin/eap_am_tools_cygwin.cpp
endif

ifeq (cygwin,$(EAP_OSTYPE))
LIBS := $(LIBS) $(CYG_OPENSSL_LIBRARY)/libssl.a $(CYG_OPENSSL_LIBRARY)/libcrypto.a
else
LIBS := $(LIBS) $(CYG_OPENSSL_LIBRARY)/libssl.so $(CYG_OPENSSL_LIBRARY)/libcrypto.so
endif

ifeq (cygwin,$(EAP_OSTYPE))
ifdef DMALLOC
	LIBS := $(LIBS) $(WLAN_WINDOWS)/LIBRARY/windows/dmalloc_dll.lib
endif
endif

include $(WLAN_LINUX)/base.mak

# end
