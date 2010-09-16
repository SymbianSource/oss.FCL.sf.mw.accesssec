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

#if !defined(_TLS_MESSAGE_H_)
#define _TLS_MESSAGE_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "tls_record_message.h"
#include "abs_tls_message_hash.h"
#include "abs_tls_apply_cipher_spec.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_MESSAGE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_MESSAGE_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_MESSAGE_H 
	#define EAP_FUNC_EXPORT_TLS_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_MESSAGE_H 
#elif defined(EAP_EXPORT_TLS_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_MESSAGE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_MESSAGE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_MESSAGE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_MESSAGE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_MESSAGE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_MESSAGE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_MESSAGE_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


//----------------------------------------------------------------------------


/// This class defines one TLS-message. One TLS message could include many TLS-records.
/**
 * This class defined one TLS-message.
 * Parse and analyse of TLS-message is asyncronous.
 * m_analyse_index tells the index of message where asyncronous
 * analyse of TLS-message must continue.
 * Analysed messages are skipped during the asyncronous
 * analyse of messages. Asyncronous analyse is needed
 * because of the PKI functions are asyncronous in
 * Symbian.
 */
class EAP_CLASS_VISIBILITY_TLS_MESSAGE_H tls_message_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to interface of message HASH creation. See abs_tls_message_hash_c.
	abs_tls_message_hash_c * const m_message_hash;

	/// This is pointer to interface of apply cipher spec. See abs_tls_apply_cipher_spec_c.
	abs_tls_apply_cipher_spec_c * const m_apply_cipher_spec;

	/// This is pointer to interface of change cipher spec. See abs_tls_change_cipher_spec_c.
	abs_tls_change_cipher_spec_c * m_change_cipher_spec;

	/// This buffer includes copy of the whole received TLS-message data.
	eap_variable_data_c m_tls_message_data;

	/// This is EAP-identifier of the EAP-packet that includes TLS-message. This is needed in XP-PEAP.
	u8_t m_received_eap_identifier;

	/// This is the index of message where asyncronous analyse of TLS-message must continue.
	u32_t m_analyse_index;

	/// This array includes one or more records.
	eap_array_c<tls_record_message_c> m_record_messages;

	/// This indicates whether this object is client (true) or server (false). This is mostly for traces.
	const bool m_is_client;

	/// This flag tells the send message includes TLS-Handshake message.
	/// Note the received messages are not marked.
	/// This information is needed in special PEAP version.
	/// All messages including TLS-Handshake message must have PEAP L bit and four octet TLS message length field.
	bool m_includes_tls_handshake_message;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the tls_message_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H virtual ~tls_message_c();

	/**
	 * The constructor of the tls_message_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H tls_message_c(
		abs_eap_am_tools_c * const tools,
		abs_tls_message_hash_c * const message_hash,
		abs_tls_apply_cipher_spec_c * const apply_cipher_spec,
		abs_tls_change_cipher_spec_c * const change_cipher_spec,
		const bool is_client);

	/**
	 * This function resets this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_status_e reset();

	/**
	 * This function returns the index of message where analyse must continue.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H u32_t get_analyse_index() const;

	/**
	 * This function saves the index of message where analyse must continue.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H void save_analyse_index(const u32_t analyse_index);

	/**
	 * This function copies the received TLS-message data and EAP-identifier.
	 * EAP-identifier is needed in XP PEAPv0. That stupid version uses
	 * same EAP-identifier with PEAP header and tunneled EAP-header.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_status_e set_tls_message_data(
		eap_variable_data_c * const tls_message_data,
		const u8_t received_eap_identifier);

	/**
	 * This function returns the TLS-message data.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_variable_data_c * get_tls_message_data();

	/**
	 * This function returns the EAP-identifier.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H u8_t get_received_eap_identifier();

	/**
	 * This function adds TLS-record to m_record_messages.
	 * Parameter free_record tells whether record must be freed in destructor.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_status_e add_record_message(
		tls_record_message_c * const record,
		const bool free_record,
		const bool includes_tls_handshake_message);

	/**
	 * This function fragments TLS-protocol messages to one or more TLS-record messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_status_e fragment_tls_records(
		tls_record_message_c * const tls_record_message,
		eap_array_c<tls_record_message_c> * const tls_fragments);

	/**
	 * This function adds data of every TLS-record to tls_message_buffer.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_status_e add_message_data(
		eap_variable_data_c * const tls_message_buffer,
		bool * const includes_tls_handshake_message);

	/**
	 * This function returns count of the TLS-records.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H u32_t get_record_message_count() const;

	/**
	 * This function returns pointer to the TLS-record selected by index.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H tls_record_message_c * get_record_message(
		const u32_t index) const;

	/**
	 * This function removes the TLS-record selected by index.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H eap_status_e remove_record_message(
		const u32_t index);

	/**
	 * This function returns pointer to the last TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_MESSAGE_H tls_record_message_c * get_last_record_message() const;

	// 
	//--------------------------------------------------
}; // class tls_message_c


//--------------------------------------------------

#endif //#if !defined(_TLS_MESSAGE_H_)



// End.
