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

#if !defined(_ABS_TLS_MESSAGE_HASH_H_)
#define _ABS_TLS_MESSAGE_HASH_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_TLS_MESSAGE_HASH_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_MESSAGE_HASH_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_MESSAGE_HASH_H 
	#define EAP_FUNC_EXPORT_ABS_TLS_MESSAGE_HASH_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_MESSAGE_HASH_H 
#elif defined(EAP_EXPORT_ABS_TLS_MESSAGE_HASH_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_MESSAGE_HASH_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_MESSAGE_HASH_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_MESSAGE_HASH_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_MESSAGE_HASH_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_MESSAGE_HASH_H 
#endif
// End: added by script change_export_macros.sh.

/// This class declares the functions message classes of TLS
/// requires from the TLS.
class EAP_CLASS_VISIBILITY_ABS_TLS_MESSAGE_HASH_H abs_tls_message_hash_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing.
	virtual ~abs_tls_message_hash_c()
	{
	}

	/// Constructor does nothing.
	abs_tls_message_hash_c()
	{
	}

	/**
	 * This function adds the send and received TLS-handshake message to MD5 and SHA hashes.
	 * @param eap includes the buffer of the whole reassembled TLS-packet.
	 * @param packet_length is length in bytes of the TLS-packet.
	 */
	virtual eap_status_e message_hash_update(
		const bool true_when_parse_message,
		const tls_handshake_type_e type,
		u8_t * const tls_packet,
		const u32_t tls_packet_length) = 0;

	/**
	 * This function saves MD5 and SHA hashes for certificate verify message to
	 * member attributes m_message_hash_md5_certificate_verify and m_message_hash_sha1_certificate_verify.
	 */
	virtual eap_status_e message_hash_save_certificate_verify() = 0;

	/**
	 * This function saves MD5 and SHA hashes for finished message to
	 * member attributes message_hash_md5_finished and message_hash_sha1_finished.
	 */
	virtual eap_status_e message_hash_save_finished(
		const bool client_originated) = 0;

	/**
	 * This function creates finished message hash.
	 * @param signed_message_hash is pointer to buffer of the message hash.
	 */
	virtual eap_status_e message_hash_create_finished(
		const bool client_originated_message,
		eap_variable_data_c * const signed_message_hash) = 0;

	//--------------------------------------------------
}; // class abs_tls_message_hash_c

#endif //#if !defined(_ABS_TLS_MESSAGE_HASH_H_)

//--------------------------------------------------



// End.
