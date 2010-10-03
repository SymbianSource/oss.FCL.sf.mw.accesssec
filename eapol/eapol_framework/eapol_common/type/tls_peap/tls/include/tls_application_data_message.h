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

#if !defined(_TLS_APPLICATION_DATA_MESSAGE_H_)
#define _TLS_APPLICATION_DATA_MESSAGE_H_

#include "eap_tools.h"
#include "eap_array.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H 
	#define EAP_FUNC_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H 
#elif defined(EAP_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H)
	#define EAP_CLASS_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H 
	#define EAP_C_FUNC_EXPORT_TLS_APPLICATION_DATA_MESSAGE_H 
#endif
// End: added by script change_export_macros.sh.


class eap_buf_chain_wr_c;


/** @file */

//----------------------------------------------------------------------------

/// This class defines one TLS application data message.
/**
 * This class includes one application data message.
 */
class EAP_CLASS_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H tls_application_data_message_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	/// This attribute includes the application data.
	eap_variable_data_c m_application_data;

	/// This indicates whether this object is client (true) or server (false). This mostly for traces.
	bool m_is_client;

	/// This flag tells this message is analysed.
	bool m_is_analysed;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	//--------------------------------------------------

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H void set_is_valid();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor does nothing.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H virtual ~tls_application_data_message_c();

	/**
	 * Constructor initializes the object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H tls_application_data_message_c(
		abs_eap_am_tools_c * const tools,
		const bool is_client);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H bool get_is_valid();

	/**
	 * This function sets this message is analysed.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H void set_is_analysed();

	/**
	 * This function returns whether message is analysed (true) or not (false).
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H bool get_is_analysed();


	/**
	 * This function stores the application data to m_application_data.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H eap_status_e set_application_data(
		const u8_t * const packet,
		const u32_t packet_length);

	/**
	 * This function returns pointer to m_application_data.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H eap_variable_data_c * get_application_data();

	/**
	 * This function adds data of the TLS-Application data message from m_application_data to tls_message_buffer.
	 */
	EAP_FUNC_VISIBILITY_TLS_APPLICATION_DATA_MESSAGE_H eap_status_e add_message_data(
		eap_variable_data_c * const tls_message_buffer);

	// 
	//--------------------------------------------------
}; // class tls_application_data_message_c


//--------------------------------------------------

#endif //#if !defined(_TLS_APPLICATION_DATA_MESSAGE_H_)



// End.
