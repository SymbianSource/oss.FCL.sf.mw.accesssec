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

#if !defined(_TLS_RECORD_MESSAGE_H_)
#define _TLS_RECORD_MESSAGE_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "tls_record_header.h"
#include "tls_handshake_message.h"
#include "tls_change_cipher_spec_message.h"
#include "tls_alert_message.h"
#include "tls_application_data_message.h"
#include "abs_tls_message_hash.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_RECORD_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H 
	#define EAP_FUNC_EXPORT_TLS_RECORD_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_MESSAGE_H 
#elif defined(EAP_EXPORT_TLS_RECORD_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_RECORD_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_MESSAGE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_RECORD_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_RECORD_MESSAGE_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */

//----------------------------------------------------------------------------

/**
 * This class defines one TLS record message.
 * Note the protocols are exclusive. Only one protocol is allowed in one record message.
 * The m_protocol attribute of m_tls_record_header attribute tells the used protocol.
 * Parse and analyse of TLS-records is asyncronous.
 * m_analyse_index tells the index of message where asyncronous
 * analyse of TLS-record must continue.
 * Analysed records are skipped during the asyncronous
 * analyse of records. Asyncronous analyse is needed
 * because of the PKI functions are asyncronous in
 * Symbian.
 */
class EAP_CLASS_VISIBILITY_TLS_RECORD_MESSAGE_H tls_record_message_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to interface of message HASH creation. See abs_tls_message_hash_c.
	abs_tls_message_hash_c * const m_message_hash;

	/// This is the protocol of the TLS-record. See tls_record_protocol_e.
	tls_record_protocol_e m_protocol;

	/// This is the version of the TLS-record.
	tls_version_e m_version;

	/// This is the length of the data of the TLS-record, not including the header.
	/// The length (in bytes) of the following TLSPlaintext.fragment (TLS-record data). The length should not exceed 2^14.
	u32_t m_length;

	/// This flag tells the TLS-record header is included to m_record_message_data.
	bool m_tls_record_header_is_included;

	/// This buffer is used both sent and received TLS-records.
	/// This buffer includes reference to the record included in the whole received TLS-message (header+data) in tls_message_c.
	/// This buffer includes whole data of TLS-record of sent TLS-message.
	eap_variable_data_c m_record_message_data;

	/// This is the index of message where asyncronous analyse of TLS-message must continue.
	u32_t m_analyse_index;

	/// This flag tells this record is parsed.
	bool m_parsed_record;

	/// This flag tells whether the cipher suite is applied to this record (true) or not (false).
	bool m_cipher_suite_applied;

	/// This array includes Handshake messages. There could be many handshake messages.
	eap_array_c<tls_handshake_message_c> m_handshake_messages;
	/// This array includes ChangeCipherSpec messages. Normally there should be only one message.
	eap_array_c<tls_change_cipher_spec_message_c> m_change_cipher_spec_messages;
	/// This array includes Alert messages. Normally there should be only one message.
	eap_array_c<tls_alert_message_c> m_alert_messages;
	/// This array includes Application data messages.
	eap_array_c<tls_application_data_message_c> m_application_data_messages;

	/// This indicates whether this object is client (true) or server (false). This is mostly for traces.
	const bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the tls_record_message_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H virtual ~tls_record_message_c();

	/**
	 * The constructor of the tls_record_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H tls_record_message_c(
		abs_eap_am_tools_c * const tools,
		abs_tls_message_hash_c * const message_hash,
		const bool is_client);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H bool get_is_valid();


	/**
	 * This function returns the index of message where analyse must continue.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H u32_t get_analyse_index() const;

	/**
	 * This function saves the index of message where analyse must continue.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H void save_analyse_index(const u32_t analyse_index);


	/**
	 * This function returns the flag that tells whether this record is parsed (true) or not (flase).
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H bool get_parsed_record() const;

	/**
	 * This function sets the flag that tells this record is parsed.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H void set_parsed_record();


	/**
	 * This function returns the flag that tells whether the TLS-record header is included to m_record_message_data (true) or not (flase).
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H bool get_tls_record_header_is_included() const;

	/**
	 * This function sets the flag that tells whether the TLS-record header is included to m_record_message_data (true) or not (flase).
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H void set_tls_record_header_is_included(const bool when_true_tls_record_header_is_included);


	/**
	 * This function returns the flag that tells whether the cipher suite is applied to this record (true) or not (flase).
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H bool get_cipher_suite_applied() const;

	/**
	 * This function sets the flag that tells the cipher suite is applied to this record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H void set_cipher_suite_applied();


	/**
	 * This function sets the protocol of this record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e set_protocol(
		tls_record_protocol_e protocol);

	/**
	 * This function sets the version of TLS.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e set_version(
		tls_version_e version);

	/**
	 * This function copies the appropriate fields of this record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e set_record_header_copy(
		const tls_record_header_c * const tls_record_header);

	/**
	 * This function sets the reference of TLS-record data.
	 * NOTE this does not copy the message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e set_record_message_data(
			void * const data,
			const u32_t data_length);

	/**
	 * This function returns the reference of TLS-record data.
	 * NOTE this is not a copy of the message.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_variable_data_c * get_record_message_data();

	/**
	 * This function returns the protocol of TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H tls_record_protocol_e get_protocol() const;

	/**
	 * This function returns the version of TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H tls_version_e get_version() const;

	/**
	 * This function returns the data length of TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H u32_t get_data_length() const;

	/**
	 * This function adds the data length of TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e add_data_length(const u32_t data_length);

	/**
	 * This function adds TLS-handshake message to this TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e add_handshake_message(
		tls_handshake_message_c * const handshake_message,
		const bool free_handshake_message);

	/**
	 * This function adds TLS-change cipher spec message to this TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e add_change_cipher_spec_message(
		tls_change_cipher_spec_message_c * const change_cipher_spec_message,
		const bool free_change_cipher_spec_message);

	/**
	 * This function adds TLS-alert message to this TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e add_alert_message(
		tls_alert_message_c * const alert_message,
		const bool free_alert_message);

	/**
	 * This function adds TLS-application data message to this TLS-record.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e add_application_data_message(
		tls_application_data_message_c * const alert_message,
		const bool free_alert_message);

	/**
	 * This function adds data of every TLS-protocol message to internal message buffer (m_record_message_data).
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H eap_status_e add_message_data();

	/**
	 * This function returns count of the TLS-handshake messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H u32_t get_handshake_count() const;

	/**
	 * This function returns count of the TLS-change cipher spec messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H u32_t get_change_cipher_spec_count() const;

	/**
	 * This function returns count of the TLS-alert messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H u32_t get_alert_count() const;

	/**
	 * This function returns count of the TLS-application data messages.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H u32_t get_application_data_count() const;

	/**
	 * This function returns the TLS-handshake message selected by index.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H tls_handshake_message_c * get_handshake(
		const u32_t index) EAP_TEMPLATE_CONST;

	/**
	 * This function returns the TLS-change cipher spec message selected by index.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H const tls_change_cipher_spec_message_c * get_change_cipher_spec(
		const u32_t index) const;

	/**
	 * This function returns the TLS-alert message selected by index.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H const tls_alert_message_c * get_alert(
		const u32_t index) const;

	/**
	 * This function returns the TLS-application data message selected by index.
	 */
	EAP_FUNC_VISIBILITY_TLS_RECORD_MESSAGE_H tls_application_data_message_c * get_application_data(
		const u32_t index) const;

	// 
	//--------------------------------------------------
}; // class tls_record_message_c


//--------------------------------------------------

#endif //#if !defined(_TLS_RECORD_MESSAGE_H_)



// End.
