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

#if !defined(_TLS_CHANGE_CIPHER_SPEC_MESSAGE_H_)
#define _TLS_CHANGE_CIPHER_SPEC_MESSAGE_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "abs_tls_change_cipher_spec.h"


/** @file */

/**
 * This is enumeration of change cipher spec messages.
 */
enum tls_change_cipher_spec_type_e
{
	tls_change_cipher_spec_type_change_cipher_spec = (1), ///< This is the only one that is defined.
	tls_change_cipher_spec_type_none = (255), ///< This is initialization value that means no type is defined.
 };

//----------------------------------------------------------------------------

/// This class defines one TLS change cipher spec message.
/**
 * This class includes data of TLS-ChangeCipherSpec message.
 */
class EAP_EXPORT tls_change_cipher_spec_message_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to interface of TLS-record.
	/// Interface includes function to inform change cipher spec related events.
	abs_tls_change_cipher_spec_c * m_change_cipher_spec;

	/// This buffer includes data of TLS-ChangeCipherSpec message.
	eap_variable_data_c m_tls_change_cipher_spec_message_buffer;

	tls_change_cipher_spec_type_e m_type;

	/// This indicates whether this object is client (true) or server (false). This mostly for traces.
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_IMPORT void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~tls_change_cipher_spec_message_c();

	/**
	 * Constructor initializes class.
	 */
	EAP_FUNC_IMPORT tls_change_cipher_spec_message_c(
		abs_eap_am_tools_c * const tools,
		abs_tls_change_cipher_spec_c * const change_cipher_spec,
		const bool is_client);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_IMPORT bool get_is_valid();

	/**
	 * This function creates data of the Handshake message to internal buffer.
	 * Later this data is added to final TLS-record buffer.
	 */
	EAP_FUNC_IMPORT eap_status_e create_message_data();


	/**
	 * This function sets the change cipher spec message type.
	 */
	EAP_FUNC_IMPORT eap_status_e set_change_cipher_spec_type(tls_change_cipher_spec_type_e type);

	/**
	 * This function gets the change cipher spec message type.
	 */
	EAP_FUNC_IMPORT tls_change_cipher_spec_type_e get_change_cipher_spec_type() const;

	/**
	 * This function adds data of the TLS-CahneCipherSpec data message from m_tls_change_cipher_spec_message_buffer to tls_message_buffer.
	 */
	EAP_FUNC_IMPORT eap_status_e add_message_data(
		eap_variable_data_c * const tls_message_buffer);

	// 
	//--------------------------------------------------
}; // class tls_change_cipher_spec_message_c


//--------------------------------------------------

#endif //#if !defined(_TLS_CHANGE_CIPHER_SPEC_MESSAGE_H_)



// End.
