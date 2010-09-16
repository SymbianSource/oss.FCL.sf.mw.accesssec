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

#if !defined(_TLS_ALERT_MESSAGE_H_)
#define _TLS_ALERT_MESSAGE_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "tls_peap_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_ALERT_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H 
	#define EAP_FUNC_EXPORT_TLS_ALERT_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_ALERT_MESSAGE_H 
#elif defined(EAP_EXPORT_TLS_ALERT_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_ALERT_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_ALERT_MESSAGE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_ALERT_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_ALERT_MESSAGE_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */


/// This class defines one TLS alert message.
/**
 * This class defines TLS-Alert message.
 */
class EAP_CLASS_VISIBILITY_TLS_ALERT_MESSAGE_H tls_alert_message_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is buffer for geneated TLS-Alert message.
	eap_variable_data_c m_tls_alert_message_buffer;

	/// This is the alert level.
	tls_alert_level_e m_alert_level;

	/// This is the alert description.
	tls_alert_description_e m_alert_description;

	/// This indicates whether this object is client (true) or server (false). This mostly for traces.
	bool m_is_client;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing.
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H virtual ~tls_alert_message_c();

	/// Constructor initializes the object.
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H tls_alert_message_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client);


	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H bool get_is_valid();


	/**
	 * This function creates data of the Handshake message to internal buffer.
	 * Later this data is added to final TLS-record buffer.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H eap_status_e create_message_data();



	/**
	 * This function sets alert level.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H eap_status_e set_alert_level(const tls_alert_level_e alert_level);

	/**
	 * This function gets alert level.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H tls_alert_level_e get_alert_level() const;


	/**
	 * This function sets alert description.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H eap_status_e set_alert_description(const tls_alert_description_e alert_description);

	/**
	 * This function gets alert description.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H tls_alert_description_e get_alert_description() const;


	/**
	 * This function adds data of the TLS-Alert message to tls_message_buffer.
	 */
	EAP_FUNC_VISIBILITY_TLS_ALERT_MESSAGE_H eap_status_e add_message_data(
		eap_variable_data_c * const tls_message_buffer);

	// 
	//--------------------------------------------------
}; // class tls_alert_message_c


//--------------------------------------------------

#endif //#if !defined(_TLS_ALERT_MESSAGE_H_)



// End.
