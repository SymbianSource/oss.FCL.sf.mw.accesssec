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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

#if !defined(_EAPOL_RSNA_KEY_HEADER_H_)
#define _EAPOL_RSNA_KEY_HEADER_H_

#include "eapol_header.h"
#include "eap_general_header_base.h"
#include "eapol_key_header.h"
#include "eapol_key_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_RSNA_KEY_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_HEADER_H 
#elif defined(EAP_EXPORT_EAPOL_RSNA_KEY_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


//------------------------------------------------------

/// This is base class of EAPOL RSNA key header.
/**
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                                 +-+-+-+-+-+-+-+-+
 *                                                 | EAPOL Version |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  EAPOL Type   |   EAPOL Packet Body Length    | Descriptor Ty.|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key Information               | Key Length                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key Replay Counter 8 octets                                   |
 * +-                                                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key Nonce 32 octets                                           |
 * +-                                                             -+
 * :                                                               :
 * +-                                                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | EAPOL-Key IV 16 octets                                        |
 * +-                                                             -+
 * :                                                               :
 * +-                                                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key RSC 8 octets                                              |
 * +-                                                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | STA MAC Address 6 octets                                      |
 * +-                             -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               | Reserved                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key MIC 16 octets                                             |
 * +-                                                             -+
 * :                                                               :
 * +-                                                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key Data Length (n) 2 octets                                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Key Data n octets                                             |
 * +-                                                             -+
 * :                                                               :
 * +-                                                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eapol_RSNA_key_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This flag indicates whether the message is RSNA (true) or WPA (false).
	bool m_is_RSNA_when_true;

	/// This flag indicates whether the message is WPXM (true) or not (false).
	bool m_is_WPXM_when_true;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/// This is enumeration of Key Information bit masks.
	enum key_information_bit_masks_e
	{
		m_key_information_mask_key_descriptor_version  = 0x0007, ///< 3 bits wide
		m_key_information_mask_key_type                = 0x0008, ///< 1 bits wide
		m_key_information_mask_reserved_a_RSNA         = 0x0030, ///< 2 bits wide, this is RSNA specific.
		m_key_information_mask_key_index_WPA           = 0x0030, ///< 2 bits wide, this is WPA specific.
		m_key_information_mask_install                 = 0x0040, ///< 1 bit  wide
		m_key_information_mask_key_ack                 = 0x0080, ///< 1 bit  wide
		m_key_information_mask_key_MIC                 = 0x0100, ///< 1 bit  wide
		m_key_information_mask_secure                  = 0x0200, ///< 1 bit  wide
		m_key_information_mask_error                   = 0x0400, ///< 1 bit  wide
		m_key_information_mask_request                 = 0x0800, ///< 1 bit  wide
		m_key_information_mask_encrypted_key_data_RSNA = 0x1000, ///< 1 bit  wide, this is RSNA specific.
		m_key_information_mask_reserved_b_RSNA         = 0xe000, ///< 3 bits wide, this is RSNA specific.
		m_key_information_mask_reserved_b_WPA          = 0xf000, ///< 4 bits wide, this is WPA specific.
	};

	/// This is enumeration of Key Information bit masks.
	enum key_information_bit_shifts_e
	{
		m_key_information_mask_key_descriptor_version_shift  =  0,
		m_key_information_mask_key_type_shift                =  3,
		m_key_information_mask_reserved_a_shift_RSNA         =  4, // this is RSNA specific.
		m_key_information_mask_key_index_shift_WPA           =  4, // this is WPA specific.
		m_key_information_mask_install_shift                 =  6,
		m_key_information_mask_key_ack_shift                 =  7,
		m_key_information_mask_key_MIC_shift                 =  8,
		m_key_information_mask_secure_shift                  =  9,
		m_key_information_mask_error_shift                   = 10,
		m_key_information_mask_request_shift                 = 11,		
		m_key_information_mask_encrypted_key_data_shift_RSNA = 12, // this is RSNA specific.
		m_key_information_mask_reserved_b_shift_WPA          = 12, // this is WPA specific.
		m_key_information_mask_reserved_b_shift_RSNA         = 13, // this is RSNA specific.
	};

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/// This function sets the Key Information field.
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information(const u16_t info);
	
	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum key_descriptor_version_e
	{
		m_key_descriptor_version_none = 0,
		m_key_descriptor_version_1 = 1,
		m_key_descriptor_version_2 = 2,
	};

	enum eapol_RSNA_key_header_constants_e
	{
		EAPOL_RSNA_KEY_EAPOL_VERSION_SIZE       =   1ul,
		EAPOL_RSNA_KEY_EAPOL_TYPE_SIZE          =   1ul,
		EAPOL_RSNA_KEY_EAPOL_BODY_LENGTH_SIZE   =   2ul,

		EAPOL_RSNA_KEY_DESCRIPTOR_TYPE_SIZE     =   1ul,
		EAPOL_RSNA_KEY_KEY_INFORMATION_SIZE     =   2ul,
		EAPOL_RSNA_KEY_KEY_LENGTH_SIZE          =   2ul,
		EAPOL_RSNA_KEY_REPLY_COUNTER_SIZE       =   8ul,
		EAPOL_RSNA_KEY_NONCE_SIZE               =  32ul,
		EAPOL_RSNA_EAPOL_KEY_IV_SIZE            =  16ul,
		EAPOL_RSNA_KEY_RSC_SIZE                 =   8ul,
		EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE     =   6ul,
		EAPOL_RSNA_KEY_RESERVED_SIZE            =   2ul,
		EAPOL_RSNA_KEY_MIC_SIZE                 =  16ul,
		EAPOL_RSNA_KEY_DATA_LENGTH_SIZE         =   2ul,

		EAPOL_RSNA_KEY_DATA_PMKID_SIZE          =  16ul,
		EAPOL_RSNA_KEY_DATA_MAXIMUM_RSN_IE_SIZE = 257ul,

		EAPOL_RSNA_EAPOL_KEY_MAXIMUM_SIZE       = 0xffff,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets_e
	{
		m_offset_eapol_version            = 0ul,
		m_offset_eapol_type               = m_offset_eapol_version            + EAPOL_RSNA_KEY_EAPOL_VERSION_SIZE,
		m_offset_eapol_packet_body_length = m_offset_eapol_type               + EAPOL_RSNA_KEY_EAPOL_TYPE_SIZE,
		m_offset_key_descriptor_type      = m_offset_eapol_packet_body_length + EAPOL_RSNA_KEY_EAPOL_BODY_LENGTH_SIZE,
		m_offset_key_information          = m_offset_key_descriptor_type      + EAPOL_RSNA_KEY_DESCRIPTOR_TYPE_SIZE,
		m_offset_key_length               = m_offset_key_information          + EAPOL_RSNA_KEY_KEY_INFORMATION_SIZE,
		m_offset_key_replay_counter       = m_offset_key_length               + EAPOL_RSNA_KEY_KEY_LENGTH_SIZE,
		m_offset_key_NONCE                = m_offset_key_replay_counter       + EAPOL_RSNA_KEY_REPLY_COUNTER_SIZE,
		m_offset_EAPOL_key_IV             = m_offset_key_NONCE                + EAPOL_RSNA_KEY_NONCE_SIZE,
		m_offset_key_RSC                  = m_offset_EAPOL_key_IV             + EAPOL_RSNA_EAPOL_KEY_IV_SIZE,
		m_offset_key_STA_MAC_address      = m_offset_key_RSC                  + EAPOL_RSNA_KEY_RSC_SIZE,
		m_offset_key_reserved             = m_offset_key_STA_MAC_address      + EAPOL_RSNA_KEY_STA_MAC_ADDRESS_SIZE,
		m_offset_key_MIC                  = m_offset_key_reserved             + EAPOL_RSNA_KEY_RESERVED_SIZE,
		m_offset_key_data_length          = m_offset_key_MIC                  + EAPOL_RSNA_KEY_MIC_SIZE,
		m_offset_key_data                 = m_offset_key_data_length          + EAPOL_RSNA_KEY_DATA_LENGTH_SIZE,
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum eapol_network_type_e
	{
		eapol_network_type_none,
		eapol_network_type_RSN,
		eapol_network_type_WPA,
	};

	enum eapol_RSNA_cipher_e
	{
		eapol_RSNA_cipher_none,
		eapol_RSNA_cipher_CCMP,
		eapol_RSNA_cipher_TKIP,
		eapol_RSNA_cipher_WEP_40,
		eapol_RSNA_cipher_WEP_104,
		eapol_RSNA_cipher_SMS4,
	};

	enum eapol_RSNA_cipher_key_length_e
	{
		eapol_RSNA_cipher_key_length_none    = 0ul,
		eapol_RSNA_cipher_key_length_CCMP    = 16ul,
		eapol_RSNA_cipher_key_length_TKIP    = 32ul,
		eapol_RSNA_cipher_key_length_WEP_40  = 5ul,
		eapol_RSNA_cipher_key_length_WEP_104 = 13ul,
	};

	enum eapol_tkip_mic_failure_type_e
	{
		eapol_tkip_mic_failure_type_group_key,
		eapol_tkip_mic_failure_type_pairwise_key,
	};

	enum eapol_RSNA_key_type_e
	{
		eapol_RSNA_key_type_none,
		eapol_RSNA_key_type_EAPOL_Key_Confirmation_Key,
		eapol_RSNA_key_type_EAPOL_Key_Encryption_Key,
		eapol_RSNA_key_type_Pairwise_Transient_Key,
		eapol_RSNA_key_type_RN,
	};

	//--------------------------------------------------

	// 
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H virtual ~eapol_RSNA_key_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eapol_RSNA_key_header_c(
		abs_eap_am_tools_c * const tools,
		const bool is_RSNA_when_true,
		const bool is_WPXM_when_true,
		void * const header_begin,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eapol_protocol_version_e get_eapol_protocol_version() const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eapol_packet_type_e get_eapol_packet_type() const;

	/// Function returns pcket body field of EAPOL packet. This field is two octets in length,
	/// taken to represent an unsigned binary number. The value of this field defines the length
	/// in octets of the Packet Body field. Value of 0 indicates that there is no Packet Body field present.
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u16_t get_eapol_packet_body_length() const;

	/// This function returns whole length of the EAPOL packet.
	/// This includes EAPOL header and packet body.
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u16_t get_eapol_packet_length() const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eapol_key_descriptor_type_e get_key_descriptor_type() const;

	/// Gets the Key Information field.
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u16_t get_key_information() const;
	
	/**
	 * This function returns the Key Descriptor Version bits of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eapol_RSNA_key_header_c::key_descriptor_version_e get_key_information_key_descriptor_version() const;

	/**
	 * This function returns the Key Type bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_key_type() const;

	/**
	 * This function returns the Reserved A bits (higher ones) of Key Information field.
	 * This is RSNA specific.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t get_key_information_reserved_a() const;

	/**
	 * This function returns the key index bits (higher ones) of Key Information field.
	 * This is WPA specific.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t get_key_information_key_index() const;

	/**
	 * This function returns the Install bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_install() const;

	/**
	 * This function returns the Key Ack bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_key_ack() const;

	/**
	 * This function returns the Key MIC bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_key_MIC() const;

	/**
	 * This function returns the Secure bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_secure() const;

	/**
	 * This function returns the Error bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_error() const;

	/**
	 * This function returns the Request bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_request() const;

	/**
	 * This function returns the Encrypted Key Data bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H bool get_key_information_encrypted_key_data() const;


	/**
	 * This function returns the Reserved B bits (lower ones) of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t get_key_information_reserved_b() const;

	/**
	 * This function returns the Key Length field of the EAPOL-Key descriptor.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u16_t get_key_length() const;
	
	/**
	 * This function returns the Key Reply Counter field of the EAPOL-Key descriptor.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u64_t get_key_replay_counter() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_NONCE() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_EAPOL_key_IV() const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_RSC() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_STA_MAC_address() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_reserved() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_MIC() const;
	
	/**
	 * This function returns the Key Data Length field of the EAPOL-Key descriptor.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u16_t get_key_data_length() const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_data(const u32_t key_length) const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u8_t * get_key_data_offset(const u32_t offset, const u32_t key_length) const;

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H static u16_t get_header_length();

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_eapol_protocol_version(const eapol_protocol_version_e version);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_eapol_packet_type(const eapol_packet_type_e type);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_eapol_packet_body_length(const u32_t eapol_length);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_descriptor_type(const eapol_key_descriptor_type_e eapol_key_descriptor_type);

	/**
	 * This function sets the selected bits on.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H u16_t set_bits_on(
		u16_t key_information,
		const u16_t set_bits,
		const u32_t mask,
		const u32_t shift);

	/**
	 * This function sets the Key Descriptor Version bits of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_key_descriptor_version(const u8_t version);

	/**
	 * This function sets the Key Type bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_key_type(const bool key_type_bit_on_when_true);

	/**
	 * This function returns the key index bits (higher ones) of Key Information field.
	 * This is WPA specific.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_key_index(const u8_t key_index);

	/**
	 * This function sets the Install bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_install(const bool install_bit_on_when_true);

	/**
	 * This function sets the Key Ack bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_key_ack(const bool key_ack_bit_on_when_true);

	/**
	 * This function sets the Key MIC bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_key_MIC(const bool key_MIC_bit_on_when_true);

	/**
	 * This function sets the Secure bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_secure(const bool secure_bit_on_when_true);

	/**
	 * This function sets the Error bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_error(const bool error_bit_on_when_true);

	/**
	 * This function sets the Request bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_request(const bool request_bit_is_on_when_true);

	/**
	 * This function sets the Encrypted Key Data bit of Key Information field.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_information_encrypted_key_data(const bool encrypted_key_data_bit_is_on_when_true);

	/**
	 * This function sets the Key Length field of the EAPOL-Key descriptor.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_length(const u16_t length);
	
	/**
	 * This function sets the Key Reply Counter field of the EAPOL-Key descriptor.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_replay_counter(const u64_t reply_counter);

	/**
	 * This function sets the Key Data Length field of the EAPOL-Key descriptor.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e set_key_data_length(const u16_t key_data_length);

	/**
	 * This function zeroes the EAPOL header and EAPOL-Key descriptor header.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_EAPOL_header_and_Key_descriptor(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_key_MIC(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_key_NONCE(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_EAPOL_key_IV(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_key_RSC(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_key_STA_MAC_address(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e zero_key_reserved(
		abs_eap_am_tools_c * const tools
		);

	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e check_header() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_HEADER_H eap_status_e reset_header(
		const u8_t key_index,
		const eapol_key_authentication_type_e authentication_type,
		const eapol_RSNA_cipher_e eapol_pairwise_cipher,
		const u64_t key_reply_counter,
		const bool key_type_bit_on_when_true,
		const bool install_bit_on_when_true,
		const bool key_ack_bit_on_when_true,
		const bool key_MIC_bit_on_when_true,
		const bool secure_bit_on_when_true,
		const bool error_bit_on_when_true,
		const bool requst_bit_on_when_true,
		const bool STAKey_bit_on_when_true,
		const bool encrypted_key_data_bit_on_when_true,
		const eapol_protocol_version_e received_eapol_version,
		const eapol_key_descriptor_type_e received_key_descriptor_type);
	
	// 
	//--------------------------------------------------
}; // class eapol_RC4_key_header_c


#endif //#if !defined(_EAPOL_KEY_H_)

//------------------------------------------------------



// End.
