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

#if !defined(_TLS_HANDSHAKE_HEADER_H_)
#define _TLS_HANDSHAKE_HEADER_H_

#include "eap_tools.h"
#include "eap_header.h"
#include "eap_general_header_base.h"
#include "tls_peap_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_HANDSHAKE_HEADER_H)
	#define EAP_CLASS_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_HANDSHAKE_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_HANDSHAKE_HEADER_H 
	#define EAP_FUNC_EXPORT_TLS_HANDSHAKE_HEADER_H 
	#define EAP_C_FUNC_EXPORT_TLS_HANDSHAKE_HEADER_H 
#elif defined(EAP_EXPORT_TLS_HANDSHAKE_HEADER_H)
	#define EAP_CLASS_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_HANDSHAKE_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_HANDSHAKE_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_HANDSHAKE_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_HANDSHAKE_HEADER_H 
	#define EAP_C_FUNC_EXPORT_TLS_HANDSHAKE_HEADER_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */

/**
 * This is enumeration of TLS-Handshake message types.
 */
enum tls_handshake_type_e
{
	tls_handshake_type_hello_request       = (0),
	tls_handshake_type_client_hello        = (1),
	tls_handshake_type_server_hello        = (2),
#if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_handshake_type_new_session_ticket  = (4),
#endif // #if defined(USE_EAP_TLS_SESSION_TICKET)
	tls_handshake_type_certificate         = (11),
	tls_handshake_type_server_key_exchange = (12),
	tls_handshake_type_certificate_request = (13),
	tls_handshake_type_server_hello_done   = (14),
	tls_handshake_type_certificate_verify  = (15),
	tls_handshake_type_client_key_exchange = (16),
	tls_handshake_type_finished            = (20),
	tls_handshake_type_none                = (255),
};

//----------------------------------------------------------------------------


/// This class defines header of TLS handshake protocol.
/**
 * Here is a figure of header of TLS handshake protocol.
 * TLS-type data follows tls_handshake_header_c.
 * @code
 *  TLS handshake-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Type: aa      | Length: h     | Length: m     | Length: l     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * Handshake message follows immediately the TLS handshake-header.
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 8-bits  m_handshake_type;  This is a protocol type field. Look at tls_handshake_type_e values.
 * 24-bits m_length;          This is a length field. Length is measured in bytes and it does not include 
 *                            m_handshake_type, m_length_high, m_length_middle and m_length_low
 *                            fields, only the length of the following handshake message.
 * @endcode
 * 
 */
class EAP_CLASS_VISIBILITY_TLS_HANDSHAKE_HEADER_H tls_handshake_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	enum sizes
	{
		m_max_data_length = TLS_PEAP_MAX_HANDSHAKE_DATA_LENGTH,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets
	{
		m_type_offset = 0ul,                                ///< This is offset of the type 8-bit field.
		m_length_offset = m_type_offset+sizeof(u8_t),       ///< This is offset of the length 24-bit field.
		m_data_offset = m_length_offset+(3ul*sizeof(u8_t)), ///< This is offset of the data.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing.
	 */
	virtual ~tls_handshake_header_c();

	/**
	 * Constructor initializes class.
	 */
	tls_handshake_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	/**
	 * This function returns TLS-handshake type.
	 */
	tls_handshake_type_e get_handshake_type() const;

	/**
	 * This function returns data length of TLS-handshake message.
	 * Length is measured in bytes and it does not include m_handshake_type, m_length_high,
	 * m_length_middle and m_length_low fields, only the length of the following handshake message.
	 */
	u32_t get_data_length() const;

	/**
	 * This function returns maximum data length of TLS-handshake message.
	 */
	static u32_t get_max_data_length();

	/**
	 * This function returns header length of TLS-handshake message.
	 */
	static u32_t get_header_length();

	/**
	 * This function returns pointer to the offset of data of TLS-handshake message.
	 */
	u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	/**
	 * This function returns pointer to data of TLS-handshake message.
	 */
	u8_t * get_data(const u32_t contignuous_bytes) const;


	/**
	 * This function returns debug string of TLS-handshake type.
	 */
	static eap_const_string get_tls_handshake_string(
		const tls_handshake_type_e type);

	/**
	 * This function returns debug string of TLS-handshake type.
	 */
	eap_const_string get_tls_handshake_string() const;

	/**
	 * This function sets the TLS-handshake type.
	 */
	void set_handshake_type(tls_handshake_type_e handshake_type);

	/**
	 * This function sets the length of data of the TLS-handshake type.
	 */
	void set_data_length(const u32_t p_length);

	/**
	 * This function resets the header of the TLS-handshake type.
	 */
	void reset_header(
		const u32_t data_length);

	/**
	 * This function checks header of TLS-handshake message.
	 */
	eap_status_e check_header() const;

	/**
	 * This function checks header of TLS-handshake message
	 * is required type.
	 */
	eap_status_e check_header(
		const tls_handshake_type_e required_type,
		const bool /*is_client_when_true*/) const;

	// 
	//--------------------------------------------------
}; // class tls_handshake_header_c


//--------------------------------------------------

#endif //#if !defined(_TLS_HANDSHAKE_HEADER_H_)



// End.
