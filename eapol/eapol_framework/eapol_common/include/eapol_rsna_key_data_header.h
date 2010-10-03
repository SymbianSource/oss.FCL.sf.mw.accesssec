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

#if !defined(_EAPOL_RSNA_KEY_DATA_HEADER_H_)
#define _EAPOL_RSNA_KEY_DATA_HEADER_H_

#include "eapol_header.h"
#include "eap_general_header_base.h"
#include "eapol_key_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H 
#elif defined(EAP_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_HEADER_H 
#endif
// End: added by script change_export_macros.sh.



//------------------------------------------------------

enum eapol_RSNA_key_descriptor_type_e
{
	eapol_RSNA_key_data_type_none             = 0x00,
	eapol_RSNA_key_data_type_RSN_IE           = 0x30,
	eapol_RSNA_key_data_type_RSN_key_data     = 0xdd,
	eapol_RSNA_key_data_type_WPA_IE           = 0xdd,
#if defined(EAP_USE_WPXM)
	eapol_RSNA_key_data_type_WPXM_reassoc_IE  = 0x9c,
#endif //#if defined(EAP_USE_WPXM)
};

enum eapol_RSNA_key_payload_type_e
{
	eapol_RSNA_key_payload_type_reserved         = 0x00,
	eapol_RSNA_key_payload_type_group_key_and_id = 0x01,
	eapol_RSNA_key_payload_type_sta_key          = 0x02,
	eapol_RSNA_key_payload_type_mac_address      = 0x03,
	eapol_RSNA_key_payload_type_pmkid            = 0x04,
	eapol_RSNA_key_payload_type_none             = 0xff,
};

enum eapol_RSNA_key_data_oui_e
{
	eapol_RSNA_key_data_oui_IEEE = 0x00000fac,
};

/**
 * This is the default trace mask for EAPOL Key Data.
 */
const u32_t TRACE_FLAGS_EAPOL_KEY_DATA_ERROR = eap_am_tools_c::eap_trace_mask_error;


/// This is base class of EAPOL RSNA key data header.
/**
 * RSN IE have identical first two bytes, Type and Length fields.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Type = 0xdd   | Length        | OUI 3 octets               ...|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | ... OUI       | Data Type     | Data (Length - 4) octets ...  :
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                             -+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_HEADER_H eapol_rsna_key_data_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This flag indicates whether the message is RSNA (true) or WPA (false).
	bool m_is_RSNA_when_true;

	/// This flag indicates whether the message is WPXM (true) or other (false).
	/// The other cases are separated with m_is_RSNA_when_true flag.
	bool m_is_WPXM_when_true;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum eapol_RSNA_key_data_header_constants_e
	{
		EAPOL_RSNA_KEY_DATA_TYPE_FIELD_SIZE           = sizeof(u8_t),
		EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_SIZE         = sizeof(u8_t),
		EAPOL_RSNA_KEY_DATA_OUI_FIELD_SIZE            = 3ul*sizeof(u8_t),
		EAPOL_RSNA_KEY_PAYLOAD_TYPE_FIELD_SIZE        = sizeof(u8_t),
		EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_MINIMUM_SIZE = 4ul,
		EAPOL_RSNA_KEY_ID_AND_GROUP_KEY_MINIMUM_SIZE  = 2ul,
		EAPOL_RSNA_KEY_ID_AND_GROUP_KEY_HEADER_SIZE   = 2ul,
		EAPOL_RSNA_STAKEY_MINIMUM_SIZE                = 1ul,
		EAPOL_RSNA_PMKID_MINIMUM_SIZE                 = 1ul,
		EAPOL_RSNA_IE_MINIMUM_SIZE                    = 4ul,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets_e
	{
		m_offset_type                  = 0ul,
		m_offset_length                = m_offset_type                  + EAPOL_RSNA_KEY_DATA_TYPE_FIELD_SIZE,
		m_offset_oui                   = m_offset_length                + EAPOL_RSNA_KEY_DATA_LENGTH_FIELD_SIZE,
		m_offset_key_data_payload_type = m_offset_oui                   + EAPOL_RSNA_KEY_DATA_OUI_FIELD_SIZE,
		m_offset_key_data_payload      = m_offset_key_data_payload_type + EAPOL_RSNA_KEY_PAYLOAD_TYPE_FIELD_SIZE,
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum eapol_RSNA_key_data_header_constants_part_2_e
	{
		EAPOL_RSNA_KEY_HEADER_LENGTH = m_offset_key_data_payload,
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eapol_rsna_key_data_header_c();

	// 
	eapol_rsna_key_data_header_c(
		abs_eap_am_tools_c * const tools,
		const bool is_RSNA_when_true,
		const bool is_WPXM_when_true,
		void * const header_begin,
		const u32_t header_buffer_length);

	eapol_RSNA_key_descriptor_type_e get_descriptor_type() const;

	u32_t get_header_and_body_length() const;

	u8_t get_length() const;

	u32_t get_oui() const;

	eapol_RSNA_key_payload_type_e get_payload_type() const;

	u32_t get_key_data_payload_length() const;

	/**
	 * This function returns pointer to the offset of Data of Key Data.
	 * @param offset is the offset of queried data in bytes.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_key_data_payload_offset(const u32_t offset, const u32_t contignuous_bytes) const;

	/**
	 * This function returns pointer to the Data of Key Data.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_key_data_payload(const u32_t contignuous_bytes) const;

	/**
	 * This function return pointer to the next eapol_rsna_key_data_header_c in the same buffer.
	 */
	u8_t * get_next_header() const;

	static u16_t get_header_length();

	eap_status_e set_type(const eapol_RSNA_key_descriptor_type_e type);

	eap_status_e set_length(const u8_t length);

	eap_status_e set_oui(const u32_t oui);

	eap_status_e set_payload_type(const eapol_RSNA_key_payload_type_e type);

	eap_status_e check_header() const;
	
	eap_status_e reset_header();
	
	/**
	 * This function returns debug strings of the EAPOL Descriptor type.
	 */
	eap_const_string get_descriptor_type_string() const;

	/**
	 * This function returns debug strings of the EAPOL Key Data type.
	 */
	eap_const_string get_payload_type_string() const;

	// 
	//--------------------------------------------------
}; // class eapol_rsna_key_data_header_c


#endif //#if !defined(_EAPOL_KEY_H_)

//------------------------------------------------------



// End.
