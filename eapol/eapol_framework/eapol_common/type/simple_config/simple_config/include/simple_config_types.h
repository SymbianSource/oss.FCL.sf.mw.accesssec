/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  This file defines the constants of the protected setup protocol.
*
*/

/*
* %version: 35 %
*/

#if !defined(_SIMPLE_CONFIG_TYPES_H_)
#define _SIMPLE_CONFIG_TYPES_H_

#include "eap_buffer.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_type_all_types.h"
#include "eap_configuration_field.h"
#include "simple_config_attribute_type.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SIMPLE_CONFIG_TYPES_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_TYPES_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_TYPES_H 
#elif defined(EAP_EXPORT_SIMPLE_CONFIG_TYPES_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_TYPES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_TYPES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_TYPES_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_TYPES_H 
#endif
// End: added by script change_export_macros.sh.


/** @file simple_config_types.h 
 *  @brief This file defines the constants of the protected setup protocol.
 */

//--------------------------------------------------

enum simple_config_Authentication_Type_e
{
	simple_config_Authentication_Type_None    = 0x0000,
	simple_config_Authentication_Type_Open    = 0x0001,
	simple_config_Authentication_Type_WPAPSK  = 0x0002,
	simple_config_Authentication_Type_Shared  = 0x0004,
	simple_config_Authentication_Type_WPA     = 0x0008,
	simple_config_Authentication_Type_WPA2    = 0x0010,
	simple_config_Authentication_Type_WPA2PSK = 0x0020,
};

enum simple_config_Encryption_Type_e
{
	simple_config_Encryption_Type_None    = 0x0001,
	simple_config_Encryption_Type_WEP     = 0x0002,
	simple_config_Encryption_Type_TKIP    = 0x0004,
	simple_config_Encryption_Type_AES     = 0x0008,
};

enum simple_config_Connection_Type_e
{
	simple_config_Connection_Type_ESS  = 0x0001,
	simple_config_Connection_Type_IBSS = 0x0002,
};

enum simple_config_Config_Methods_e
{
	simple_config_Config_Methods_USBA                 = 0x0001,
	simple_config_Config_Methods_Ethernet             = 0x0002,
	simple_config_Config_Methods_Label                = 0x0004,
	simple_config_Config_Methods_Display              = 0x0008,
	simple_config_Config_Methods_External_NFC_Token   = 0x0010,
	simple_config_Config_Methods_Integrated_NFC_Token = 0x0020,
	simple_config_Config_Methods_NFC_Interface        = 0x0040,
	simple_config_Config_Methods_PushButton           = 0x0080,
	simple_config_Config_Methods_Keypad               = 0x0100,
};

enum simple_config_State_e
{
	simple_config_State_Not_Configured = 0x0001,
	simple_config_State_Configured     = 0x0002,
};

enum simple_config_RF_Bands_e
{
	simple_config_RF_Bands_2_4_GHz = 1,
	simple_config_RF_Bands_5_0_GHz = 2,
};

enum simple_config_Association_State_e
{
	simple_config_Association_State_Not_Associated        = 0,
	simple_config_Association_State_Connection_Success    = 1,
	simple_config_Association_State_Configuration_Failure = 2,
	simple_config_Association_State_Association_Failure   = 3,
	simple_config_Association_State_IP_Failure            = 4,
};

enum simple_config_Device_Password_ID_e
{
	simple_config_Device_Password_ID_Default_PIN         = 0,
	simple_config_Device_Password_ID_User_specified      = 1,
	simple_config_Device_Password_ID_Machine_specified   = 2,
	simple_config_Device_Password_ID_Rekey               = 3,
	simple_config_Device_Password_ID_PushButton          = 4,
	simple_config_Device_Password_ID_Registrar_specified = 5,
};

enum simple_config_Configuration_Error_e
{
	simple_config_Configuration_Error_No_Error = 0,
	simple_config_Configuration_Error_OOB_Interface_Read_Error = 1,
	simple_config_Configuration_Error_Decryption_CRC_Failure = 2,
	simple_config_Configuration_Error_2_4_channel_not_supported = 3,
	simple_config_Configuration_Error_5_0_channel_not_supported = 4,
	simple_config_Configuration_Error_Signal_too_weak = 5,
	simple_config_Configuration_Error_Network_auth_failure = 6,
	simple_config_Configuration_Error_Network_association_failure = 7,
	simple_config_Configuration_Error_No_DHCP_response = 8,
	simple_config_Configuration_Error_Failed_DHCP_config = 9,
	simple_config_Configuration_Error_IP_address_conflict = 10,
	simple_config_Configuration_Error_Couldnt_connect_to_Registrar = 11,
	simple_config_Configuration_Error_Multiple_PBC_sessions_detected = 12,
	simple_config_Configuration_Error_Rogue_activity_suspected = 13,
	simple_config_Configuration_Error_Device_busy = 14,
	simple_config_Configuration_Error_Setup_locked = 15,
	simple_config_Configuration_Error_Message_Timeout = 16,
	simple_config_Configuration_Error_Registration_Session_Timeout = 17,
	simple_config_Configuration_Error_Device_Password_Auth_Failure = 18,
};

enum simple_config_Message_Type_e
{
	simple_config_Message_Type_None           = 0x00,
	simple_config_Message_Type_Beacon         = 0x01,
	simple_config_Message_Type_Probe_Request  = 0x02,
	simple_config_Message_Type_Probe_Response = 0x03,
	simple_config_Message_Type_M1             = 0x04,
	simple_config_Message_Type_M2             = 0x05,
	simple_config_Message_Type_M2D            = 0x06,
	simple_config_Message_Type_M3             = 0x07,
	simple_config_Message_Type_M4             = 0x08,
	simple_config_Message_Type_M5             = 0x09,
	simple_config_Message_Type_M6             = 0x0A,
	simple_config_Message_Type_M7             = 0x0B,
	simple_config_Message_Type_M8             = 0x0C,
	simple_config_Message_Type_WSC_ACK        = 0x0D,
	simple_config_Message_Type_WSC_NACK       = 0x0E,
	simple_config_Message_Type_WSC_DONE       = 0x0F,
	simple_config_Message_keep_this_last      = simple_config_Message_Type_WSC_DONE,
};

//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_SIMPLE_CONFIG_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("%s (0x%08x): current payload 0x%04x=%s, data length 0x%04x.\n"), \
			prefix, (payload), (payload)->get_flag_tlv_type(), \
			(payload)->get_tlv_type_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG( \
			m_am_tools, \
			TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("payload"), \
			(payload)->get_header_buffer( \
				(payload)->get_header_length()+(payload)->get_data_length()), \
			(payload)->get_header_length()+(payload)->get_data_length())); \
	}

//--------------------------------------------------

/**
 * This is the size of the local send buffer.
 */

/**
 * This is the default trace mask for SIMPLE_CONFIG and PEAP.
 */
const u32_t TRACE_FLAGS_SIMPLE_CONFIG_ERROR = eap_am_tools_c::eap_trace_mask_error;


enum simple_config_protocol_field_size_e
{
	SIMPLE_CONFIG_LOCAL_PACKET_BUFFER_LENGTH = EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH,
	SIMPLE_CONFIG_ENROLLEE_NONCE_SIZE = 16UL * sizeof(u8_t),
	SIMPLE_CONFIG_REGISTRAR_NONCE_SIZE = SIMPLE_CONFIG_ENROLLEE_NONCE_SIZE,
	SIMPLE_CONFIG_AUTH_KEY_BITS = 256ul,
	SIMPLE_CONFIG_KEY_WRAP_KEY_BITS = 128ul,
	SIMPLE_CONFIG_EMSK_BITS = 256ul,
	SIMPLE_CONFIG_AUTHENTICATOR_LENGTH = 8ul,
	SIMPLE_CONFIG_PSKn_LENGTH = 16ul,
	SIMPLE_CONFIG_ESn_LENGTH = 16ul,
	SIMPLE_CONFIG_KEY_WRAP_IV_SIZE = 16ul,
};

/**
 * This is the Diffie Hellman Prime of the SIMPLE_CONFIG.
 */
const u8_t SIMPLE_CONFIG_DIFFIE_HELLMAN_PRIME[]
	= {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

	};

/**
 * This is the Diffie Hellman Prime of the SIMPLE_CONFIG.
 */
const u8_t SIMPLE_CONFIG_DIFFIE_HELLMAN_GROUP_GENERATOR[]
	= { 0x02 };


const u8_t SIMPLE_CONFIG_VERSION = 0x10;

const u8_t SIMPLE_CONFIG_DEFAULT_NETWORK_KEY_INDEX = 1ul;

/**
 * This is the label of the SIMPLE_CONFIG-premaster secret.
 * See Chapter "8.1. Computing the master secret" in <a href="../../type/simple_config/documentation/rfc2246.txt">RFC 2246</a>.
 */
const u8_t SIMPLE_CONFIG_SECURE_KEY_DERIVATION_LABEL[] = "Wi-Fi Easy and Secure Key Derivation";

/**
 * This is the length of the label of the SIMPLE_CONFIG-premaster secret.
 */
const u32_t SIMPLE_CONFIG_SECURE_KEY_DERIVATION_LABEL_LENGTH = sizeof(SIMPLE_CONFIG_SECURE_KEY_DERIVATION_LABEL)-1ul;


const u32_t EAP_SIMPLE_CONFIG_MASTER_SESSION_KEY_SIZE = 128ul;


/**
 * This is the PCB device password PIN used in PushButton mode.
 */
const u8_t SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN[]
	= {
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	};

/**
 * This is the size of the PCB device password PIN used in PushButton mode.
 */
const u32_t SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN_SIZE = sizeof(SIMPLE_CONFIG_PBC_DEVICE_PASSWORD_PIN);


/**
 * This is the length of the RC4 key used in SIMPLE_CONFIG.
 */
const u32_t SIMPLE_CONFIG_RC4_128_KEY_LENGTH = 16ul;

/**
 * This is the length of the RC4 initialization vector used in SIMPLE_CONFIG.
 */
const u32_t SIMPLE_CONFIG_RC4_128_IV_LENGTH = 0ul;


/**
 * These are the internal SIMPLE_CONFIG-states.
 */
enum simple_config_state_e
{
	simple_config_state_none, ///< Initialization value.
	simple_config_state_wait_simple_config_start, ///< Waits start of SIMPLE_CONFIG.
	simple_config_state_process_simple_config_start,
	simple_config_state_wait_M1,
	simple_config_state_process_M1,
	simple_config_state_wait_M2,
	simple_config_state_wait_M3,
	simple_config_state_wait_M4,
	simple_config_state_wait_M5,
	simple_config_state_wait_M6,
	simple_config_state_wait_M7,
	simple_config_state_wait_M8,
	simple_config_state_wait_WSC_ACK,
	simple_config_state_wait_WSC_NACK,
	simple_config_state_wait_WSC_DONE,
	simple_config_state_pending_simple_config_messages_processed, ///< This is indication to lower layer that pending SIMPLE_CONFIG-messages are processed, new messages could be accepted..
	simple_config_state_simple_config_success, ///< SIMPLE_CONFIG authentication success.
	simple_config_state_failure, ///< Authentication failure.
};

//----------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TYPES_H network_key_and_index_c
{

private:

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	u8_t m_network_key_index;

	eap_variable_data_c m_network_key;

	bool m_is_valid;

public:

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H virtual ~network_key_and_index_c();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H network_key_and_index_c(
		abs_eap_am_tools_c * const m_am_tools);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H u8_t get_network_key_index() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H void set_network_key_index(u8_t index);

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H eap_variable_data_c * get_network_key();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H const eap_variable_data_c * get_network_key_const() const;

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H network_key_and_index_c * copy();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H bool get_is_valid();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H bool get_is_valid_data();
};

//----------------------------------------------------------------------------

/**
 *  @defgroup SIMPLE_CONFIG_config_options Configuration options of SIMPLE_CONFIG.
 *  The following configuration options are read through abs_eap_base_type_c::read_configure() function.
 *  @{
 */

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_UUID_E,
	"SIMPLE_CONFIG_UUID_E",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_UUID_R,
	"SIMPLE_CONFIG_UUID_R",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_SSID,
	"SIMPLE_CONFIG_SSID",
	eap_configure_type_hex_data,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_MAC_address,
	"SIMPLE_CONFIG_MAC_address",
	eap_configure_type_hex_data,
	false);


EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_Device_Password_ID,
	"SIMPLE_CONFIG_Device_Password_ID",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_server_Device_Password_ID,
	"SIMPLE_CONFIG_server_Device_Password_ID",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_Device_Password_ID_PIN,
	"PIN",
	eap_configure_type_string,
	false);

EAP_CONFIGURATION_FIELD(
	cf_str_SIMPLE_CONFIG_Device_Password_ID_PushButton,
	"PushButton",
	eap_configure_type_string,
	false);

/** @} */ // End of group SIMPLE_CONFIG_config_options.
//--------------------------------------------------------------------


/// This class includes the debug strings of the simple_config_cipher_suites_e, simple_config_certificate_type_e and simple_config_compression_method_e.
class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TYPES_H eap_simple_config_trace_string_c
{
public:

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H virtual ~eap_simple_config_trace_string_c();

	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H eap_simple_config_trace_string_c();

	/**
	 * Function returns string of simple_config_state_e.
	 * @param state is the queried string.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H eap_const_string get_state_string(const simple_config_state_e state) const;

	/**
	 * Function returns string of simple_config_Message_Type_e.
	 * @param type is the queried string.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H eap_const_string get_message_type_string(const simple_config_Message_Type_e type) const;

	/**
	 * Function returns string of simple_config_Attribute_Type_e.
	 * @param type is the queried string.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TYPES_H eap_const_string get_attribute_type_string(const simple_config_Attribute_Type_e type) const;

};


//--------------------------------------------------

#endif //#if !defined(_SIMPLE_CONFIG_TYPES_H_)

//--------------------------------------------------
// End.
