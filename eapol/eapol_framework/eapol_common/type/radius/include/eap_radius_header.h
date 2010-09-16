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

#if !defined(_EAP_RADIUS_HEADER_H_)
#define _EAP_RADIUS_HEADER_H_


#include "eap_general_header_base.h"
#include "eap_am_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_RADIUS_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_HEADER_H 
#elif defined(EAP_EXPORT_EAP_RADIUS_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_RADIUS_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_RADIUS_HEADER_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */

//-----------------------------------------------------------------------------------------

/// Enumeration of the RADIUS-Code values.
enum eap_radius_code_value_e
{
	eap_radius_code_none                = 0, ///< This is internal value for no type case.
	eap_radius_code_access_request      = 1, ///< 
	eap_radius_code_access_accept       = 2, ///< 
	eap_radius_code_access_reject       = 3, ///< 
	eap_radius_code_accounting_request  = 4, ///< 
	eap_radius_code_accounting_response = 5, ///< 
	eap_radius_code_access_challenge    = 11, ///< 
	eap_radius_code_maximum_supported = eap_radius_code_access_challenge, ///< Keep this the last one.
};

const u32_t EAP_RADIUS_AUTHENTICATOR_LENGTH = 16ul;

//-----------------------------------------------------------------------------------------

/** This is base class defining the RADIUS-packet header.
 * @code
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  |                         Authenticator                         |
 *  |                                                               |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Attributes ...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_RADIUS_HEADER_H eap_radius_header_base_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * This enumeration defines the offsets of the RADIUS-header fields.
	 */
	enum offsets
	{
		m_code_offset = 0ul,                                ///< This is offset to code field.
		m_identifier_offset = m_code_offset+sizeof(u8_t),   ///< This is offset to identifier field.
		m_length_offset = m_identifier_offset+sizeof(u8_t), ///< This is offset to length field.
		
		m_authenticator_offset = m_length_offset+sizeof(u16_t),
		///< This is offset to authenticator field.

		m_attributes_offset = m_authenticator_offset+EAP_RADIUS_AUTHENTICATOR_LENGTH*sizeof(u8_t),
		///< This is offset to optional attributes fields.
	};

	/// Destructor does nothing special.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H virtual ~eap_radius_header_base_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of RADIUS-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H eap_radius_header_base_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns the header length of the RADIUS-packet.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H static u32_t get_header_length();

	/// This function returns the code field of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H eap_radius_code_value_e get_code() const;

	/// This function returns the authenticator field of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H u8_t * get_authenticator() const;

	/// This function returns the length of the authenticator field of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H u32_t get_authenticator_length() const;

	/// This function returns the identifier field of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H u8_t get_identifier() const;

	/// This function returns the length field of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H u16_t get_length() const;

	/// This function returns the length of the attribute data of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H u16_t get_data_length() const;

	/// This function returns the pointer to the offset of the attribute field of RADIUS-packet.
	/// Data field includes type field.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H u8_t * get_data_offset(
		const u32_t p_offset, const u32_t p_continuous_bytes) const;


	/// This function sets the code field of the RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H void set_code(const eap_radius_code_value_e p_code);

	/// This function sets the identifier field of the RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H void set_identifier(const u8_t p_identifier);

	/// This function sets the length field of the RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H void set_length(const u16_t p_length);

	/// This function sets the length field of the RADIUS-header
	/// based on attribute data length.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H void set_data_length(const u16_t p_length);


	/// This function returns debug string of the code of the RADIUS-packet.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H eap_const_string get_code_string() const;

	/// This function checks the validity of RADIUS-header.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H eap_status_e check_header() const;


	/// This function resets the RADIUS-header.
	/// The buffer_length parameter is the length of the RADISU-header and the following attribute data buffer.
	EAP_FUNC_VISIBILITY_EAP_RADIUS_HEADER_H void reset_header(u16_t buffer_length);

	// 
	//--------------------------------------------------
}; // class eap_header_c


#endif //#if !defined(_EAP_RADIUS_HEADER_H_)

//--------------------------------------------------



// End.
