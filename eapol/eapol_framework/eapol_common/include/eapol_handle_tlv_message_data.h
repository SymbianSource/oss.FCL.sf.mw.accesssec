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

#if !defined(_EAPOL_HANDLE_TLV_MESSAGE_DATA_H_)
#define _EAPOL_HANDLE_TLV_MESSAGE_DATA_H_

#include "eap_am_types.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "eap_process_tlv_message_data.h"
#include "eap_expanded_type.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H 
	#define EAP_FUNC_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H 
#elif defined(EAP_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_HANDLE_TLV_MESSAGE_DATA_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

class eap_variable_data_c;
class eap_am_network_id_c;
class eap_buf_chain_wr_c;
class eapol_session_key_c;
class abs_eap_state_notification_c;
class eap_state_notification_c;
class network_key_and_index_c;
class simple_config_credential_c;

//----------------------------------------------------------------------------


/// This class defines functions to add and parse message data composed
/// of Attribute-Value Pairs (See eap_tlv_header_c) to/from eap_tlv_message_data_c object.
class EAP_CLASS_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H eapol_handle_tlv_message_data_c
: public eap_process_tlv_message_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_valid;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eapol_handle_tlv_message_data_c class does nothing.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H virtual ~eapol_handle_tlv_message_data_c();

	/**
	 * The constructor of the eapol_handle_tlv_message_data_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H eapol_handle_tlv_message_data_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_EAPOL_HANDLE_TLV_MESSAGE_DATA_H bool get_is_valid();

	// 
	//--------------------------------------------------
}; // class eapol_handle_tlv_message_data_c


//--------------------------------------------------

#endif //#if !defined(_EAPOL_HANDLE_TLV_MESSAGE_DATA_H_)


// End.
