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

#if !defined(_TLS_RECORD_HEADER_H_)
#define _TLS_RECORD_HEADER_H_

#include "eap_tools.h"
#include "eap_header.h"
#include "eap_general_header_base.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_RECORD_HEADER_H)
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_HEADER_H 
	#define EAP_FUNC_EXPORT_TLS_RECORD_HEADER_H 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_HEADER_H 
#elif defined(EAP_EXPORT_TLS_RECORD_HEADER_H)
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_RECORD_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_RECORD_HEADER_H 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


/**
 * This is enumeration of TLS-versions.
 */
enum tls_version_e
{
	tls_version_illegal = 0x0000,
	tls_version_3_1     = 0x0301,
	tls_version_last    = 0x0301, ///< keep this same as the last acceptable version.
};


/**
 * This is enumeration of TLS-record protocols.
 */
enum tls_record_protocol_e
{
	tls_record_protocol_change_cipher_spec = (20), ///< This is change cipher spec.
	tls_record_protocol_alert = (21),              ///< This is alert.
	tls_record_protocol_handshake = (22),          ///< This is handshake.
	tls_record_protocol_application_data = (23),   ///< This is application data.
	tls_record_protocol_none = (255),              ///< This is initialization value. Meaning is no protocol selected.
};


//----------------------------------------------------------------------------


/// This class defines header of TLS record.
/**
 * Here is a figure of header of TLS record.
 * TLS-record data follows tls_record_header_c.
 * @code
 *  TLS record-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Protocol: aa  | Version: 3    | Version: 1    | Length: m     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Length: n     |                                                
 * +-+-+-+-+-+-+-+-+                                                
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 8-bits  m_protocol; This is a TLS-protocol field.
 * 16-bits m_version;  This is a TLS-version.
 * 16-bits m_length;   This is a length field. The length (in bytes) of
 *                     the following TLSPlaintext.fragment (TLS-record data).
 *                     The length should not exceed 2^14.
 * @endcode
 * 
 */
class EAP_CLASS_VISIBILITY_TLS_RECORD_HEADER_H tls_record_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets
	{
		m_protocol_offset = 0ul,                           ///< This is offset of the protocol 8-bit field.
		m_version_offset = m_protocol_offset+sizeof(u8_t), ///< This is offset of the version 16-bit field.
		m_length_offset = m_version_offset+sizeof(u16_t),  ///< This is offset of the length 16-bit field.
		m_data_offset = m_length_offset+sizeof(u16_t),     ///< This is offset of the data of TLS-record.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing.
	virtual ~tls_record_header_c();

	/// Constructor initializes the class.
	tls_record_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns protocol of the TLS-record.
	tls_record_protocol_e get_protocol() const;

	/// This function returns version of the TLS-record.
	tls_version_e get_version() const;

	/// This function returns data length of the TLS-record.
	/// The length (in bytes) of the following TLSPlaintext.fragment (TLS-record data). The length should not exceed 2^14.
	u16_t get_data_length() const;

	/// This function returns header length of the TLS-record. This includes only protocol, version and length fiels.
	static u32_t get_header_length();

	/// This function returns pointer to offset of the TLS-record data.
	/// @param offset is the offset of queried data in bytes.
	/// @param contignuous_bytes is the length of queried data in bytes.
	u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	/// This function returns pointer to begin of the TLS-record data.
	/// @param contignuous_bytes is the length of queried data in bytes.
	u8_t * get_data(const u32_t contignuous_bytes) const;


	static eap_const_string get_tls_protocol_string(const tls_record_protocol_e protocol);

	/// This function returns debug strings of the TLS-protocol values.
	eap_const_string get_tls_protocol_string() const;

	/// This function sets the protocol of TLS-record.
	void set_protocol(tls_record_protocol_e protocol);

	/// This function sets the version of the TLS-record.
	void set_version(tls_version_e version);

	/// This function sets the data length of the TLS-record.
	void set_data_length(const u16_t p_length);

	/// This function resets the TLS-record header.
	void reset_header(
		const u16_t buffer_length,
		const tls_version_e version);

	/// This function checks the header is valid.
	eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class tls_record_header_c


//--------------------------------------------------

#endif //#if !defined(_TLS_RECORD_HEADER_H_)



// End.
