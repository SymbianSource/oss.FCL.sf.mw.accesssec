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




#if !defined(_ABS_EAP_AM_TYPE_TLS_PEAP_H_)
#define _ABS_EAP_AM_TYPE_TLS_PEAP_H_

#include "eap_am_export.h"

class eap_am_network_id_c;


/// This class declares the functions adaptation module of EAP-TLS/PEAP EAP type
/// requires from the EAP-TLS/PEAP EAP type.
class EAP_EXPORT abs_eap_am_type_tls_peap_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~abs_eap_am_type_tls_peap_c()
	{
	}

	// 
	abs_eap_am_type_tls_peap_c()
	{
	}

	virtual bool get_is_client() = 0;

	/** Client adaptation module of EAP-TLS/PEAP type calls this function.
	 *  AM gives identity to EAP-TLS/PEAP type.
	 *  This function completes asyncronously query_eap_identity() function call.
	 *  The parameter completion_status must be eap_status_ok when query is successfull.
	 */
	virtual eap_status_e complete_eap_identity_query(
		const eap_variable_data_c * const user_certificate_identity,
		const eap_am_network_id_c * const receive_network_id,
		const u8_t eap_identifier,
		const eap_status_e completion_status,
		const bool use_manual_username,
		const eap_variable_data_c * const manual_username,
		const bool use_manual_realm,
		const eap_variable_data_c * const manual_realm
		) = 0;


	//--------------------------------------------------
}; // class abs_eap_am_type_tls_peap_c

#endif //#if !defined(_ABS_EAP_AM_TYPE_TLS_PEAP_H_)

//--------------------------------------------------



// End.
