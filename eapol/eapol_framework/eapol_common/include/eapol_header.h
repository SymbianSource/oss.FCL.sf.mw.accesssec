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

#if !defined(_EAPOL_HEADER_H_)
#define _EAPOL_HEADER_H_


#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_header.h"
#include "eap_general_header_base.h"
#include "eapol_key_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_HEADER_H 
	#define EAP_FUNC_EXPORT_EAPOL_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_HEADER_H 
#elif defined(EAP_EXPORT_EAPOL_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

/**
 * Enumeration of EAPOL Protocol Version.
 */
enum eapol_protocol_version_e
{
	eapol_protocol_version_none = 0, ///< This is internal value for no version case.
	eapol_protocol_version_1 = 1, ///< This is the original Protocol Version.
	eapol_protocol_version_2 = 2, ///< This is the new Protocol Version defined in new IEEE P802.1X.
};

/**
 * Enumeration of EAPOL packet type.
 */
enum eapol_packet_type_e
{
	eapol_packet_type_eap           = 0, ///< This the EAP-Packet.
	eapol_packet_type_start         = 1, ///< This is EAPOL-Start.
	eapol_packet_type_logoff        = 2, ///< This is EAPOL-Logoff.
	eapol_packet_type_key           = 3, ///< This is EAPOL-Key.
	eapol_packet_type_enc_asf_alert = 4, ///< This is EAPOL-Encapsulated-ASF-Alert.
	eapol_packet_type_SAE_KE        = 5, ///< This is internal SAE testing.
	eapol_packet_type_SAE_EAP       = 6, ///< This is internal SAE testing.
	eapol_packet_type_SAE_START     = 7, ///< This is internal SAE testing.
	eapol_packet_type_SAE_LOGOFF    = 8, ///< This is internal SAE testing.
	eapol_packet_type_no_type       = 0xff, ///< This is internal value for no type case.
};


/**
 * This is base class of EAPOL header.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Prot. Version |  Packet Type  |       Data Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Data ...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAPOL_HEADER_H eapol_header_base_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/**
	 * This enumeration defines the offsets of the EAPOL-header fields.
	 */
	enum offsets
	{
		m_version_offset = 0ul,                                   ///< This is the offset of the version field.
		m_packet_type_offset = m_version_offset+sizeof(u8_t),     ///< This is the offset of the packet type field.
		m_data_length_offset = m_packet_type_offset+sizeof(u8_t), ///< This is the offset of the data length field.
		m_data_offset = m_data_length_offset+sizeof(u16_t),       ///< This is the offset of the data field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H virtual ~eapol_header_base_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of EAPOL-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eapol_header_base_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns the Protocol Version field of EAPOL header.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eapol_protocol_version_e get_version() const;

	/// This function returns the packet type field of EAPOL header.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eapol_packet_type_e get_packet_type() const;

	/// This function returns the data length of the EAPOL-packet.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H u16_t get_data_length() const;

	/// This function returns the header length of the EAPOL-packet.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H static u32_t get_header_length();

	/// This function returns pointer to the data of the EAPOL-packet.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H u8_t * get_data(const u32_t data_length) const;

	/// This function sets the Protocol Version field of the EAPOL-header.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H void set_version(const eapol_protocol_version_e p_version);

	/// This function sets the packet type field of the EAPOL-header.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H void set_packet_type(const eapol_packet_type_e p_packet_type);

	/// This function sets the data length field of the EAPOL-header.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H void set_data_length(const u16_t p_data_length);

	/// This function returns debug string of the type of the EAPOL-packet.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eap_const_string get_type_string() const;

	/// This function checks the validity of EAPOL-header.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class eapol_header_base_c




/// This is read only EAPOL header.
/// @{ This class can be removed. eapol_header_base_c could be used instead. }
class EAP_CLASS_VISIBILITY_EAPOL_HEADER_H eapol_header_rd_c
: public eapol_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H virtual ~eapol_header_rd_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of EAPOL-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eapol_header_rd_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns pointer to the header of the EAP-packet included in the EAPOL-packet.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H u8_t * get_eap_header() const;

	// 
	//--------------------------------------------------
}; // class eapol_header_rd_c




/// This is read and write EAPOL header.
/// @{ This class can be removed. eapol_header_base_c could be used instead. }
class EAP_CLASS_VISIBILITY_EAPOL_HEADER_H eapol_header_wr_c
: public eapol_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H virtual ~eapol_header_wr_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of EAPOL-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H eapol_header_wr_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns pointer to the header of the EAP-packet included in the EAPOL-packet.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H u8_t * get_eap_header();

	/// This function resets the EAPOL-header.
	/// The buffer_length parameter is the length of the EAPOL-header and the following data buffer.
	EAP_FUNC_VISIBILITY_EAPOL_HEADER_H void reset_header(u16_t buffer_length);

	// 
	//--------------------------------------------------
}; // class eapol_header_wr_c


#endif //#if !defined(_EAPOL_HEADER_H_)

//--------------------------------------------------



// End.
