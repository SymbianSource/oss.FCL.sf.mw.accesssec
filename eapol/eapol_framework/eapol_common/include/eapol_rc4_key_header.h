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

#if !defined(_EAPOL_RC4_KEY_HEADER_H_)
#define _EAPOL_RC4_KEY_HEADER_H_

#include "eapol_header.h"
#include "eapol_key_header.h"
#include "eap_general_header_base.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_RC4_KEY_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H 
	#define EAP_FUNC_EXPORT_EAPOL_RC4_KEY_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RC4_KEY_HEADER_H 
#elif defined(EAP_EXPORT_EAPOL_RC4_KEY_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RC4_KEY_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_RC4_KEY_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RC4_KEY_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RC4_KEY_HEADER_H 
#endif
// End: added by script change_export_macros.sh.



//------------------------------------------------------


enum eapol_RC4_key_header_constants_e
{
	EAPOL_RC4_KEY_IV_LENGTH = 16ul,
	EAPOL_RC4_KEY_REPLAY_COUNTER_LENGTH = 8ul,
	EAPOL_RC4_KEY_SIGNATURE_LENGTH = 16ul,
	SIZE_OF_EMPTY_EAPOL_RC4_KEY_FRAME = 48ul,
	SIZE_OF_EMPTY_EAPOL_RC4_KEY_BODY = 44ul, ///< <- This is without version, packet type and packet body length fields.
};


/// This is base class of EAPOL RC4 key header.
/**
 * This defined in <a href="../../documentation/RFCs/rfc3580.txt">rfc3580.txt</a>.
 * See chapter RC4 EAPOL-Key Frame.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                                 +-+-+-+-+-+-+-+-+
 *                                                 | EAPOL Version |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  EAPOL Type   |   EAPOL Packet Body Length    | Descriptor Ty.|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  RC4 Key Length               | RC4 Reply Counter 8 octets    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                             -+
 * |                                                               |
 * +-                             -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               | RC4 Key IV 16 octets          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                             -+
 * |                                                               |
 * +-                                                             -+
 * |                                                               |
 * +-                                                             -+
 * |                                                               |
 * +-                             -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               | RC4 Key Index |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-             -+
 * | RC4 Key Signature 16 octets                                   |
 * +-                                                             -+
 * |                                                               |
 * +-                                                             -+
 * |                                                               |
 * +-                                              +-+-+-+-+-+-+-+-+
 * |                                               |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-             -+
 * | RC4 Key n octets                                              |
 * +-                                                             -+
 * |   n = (Packet Body Length) - SIZE_OF_EMPTY_EAPOL_KEY_HEADER   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eapol_RC4_key_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	enum bit_masks_e
	{
		m_flag_mask_key_flag = 0x80,
	};

	enum bit_shifts_e
	{
		m_flag_shift_key_flag = 0x07,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets_e
	{
		m_offset_eapol_version            = 0ul,
		m_offset_eapol_type               = m_offset_eapol_version            + sizeof(u8_t),
		m_offset_eapol_packet_body_length = m_offset_eapol_type               + sizeof(u8_t),
		m_offset_key_descriptor_type      = m_offset_eapol_packet_body_length + sizeof(u16_t),
		m_offset_key_length               = m_offset_key_descriptor_type      + sizeof(u8_t),
		m_offset_replay_counter           = m_offset_key_length               + sizeof(u16_t),
		m_offset_key_IV                   = m_offset_replay_counter           + EAPOL_RC4_KEY_REPLAY_COUNTER_LENGTH,
		m_offset_key_index                = m_offset_key_IV                   + EAPOL_RC4_KEY_IV_LENGTH,
		m_offset_key_signature            = m_offset_key_index                + sizeof(u8_t),
		m_offset_data                     = m_offset_key_signature            + EAPOL_RC4_KEY_SIGNATURE_LENGTH,
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum eapol_RC4_key_header_constants_e
	{
		EAPOL_RC4_EAPOL_KEY_MAXIMUM_SIZE       = 0xffff,
	};


	// 
	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H virtual ~eapol_RC4_key_header_c();

	// 
	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eapol_RC4_key_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eapol_protocol_version_e get_eapol_protocol_version() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eapol_packet_type_e get_eapol_packet_type() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u16_t get_eapol_packet_body_length() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eapol_key_descriptor_type_e get_key_descriptor_type() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u16_t get_key_length() const;
	
	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u8_t *get_replay_counter();
	
	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u8_t *get_key_IV();

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eapol_RC4_key_flags_e get_key_flag() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u8_t get_key_index() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u8_t *get_key_signature() const;

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H static u16_t get_header_length();

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H u8_t * get_key() const;

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_eapol_protocol_version(eapol_protocol_version_e version);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_eapol_packet_type(eapol_packet_type_e type);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_eapol_packet_body_length(u16_t eapol_length);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_key_descriptor_type(eapol_key_descriptor_type_e eapol_key_descriptor_type);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_key_length(u16_t length);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_key_flag(eapol_RC4_key_flags_e flags);

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e set_key_index(u8_t index);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H void zero_key_signature(
		abs_eap_am_tools_c * const m_am_tools
		);

	// - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_FUNC_VISIBILITY_EAPOL_RC4_KEY_HEADER_H eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class eapol_RC4_key_header_c


#endif //#if !defined(_EAPOL_KEY_H_)

//------------------------------------------------------
//------------------------------------------------------
//------------------------------------------------------



// End.
