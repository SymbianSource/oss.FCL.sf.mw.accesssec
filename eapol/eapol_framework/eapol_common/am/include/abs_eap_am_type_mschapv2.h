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




#if !defined(_ABS_EAP_AM_TYPE_MSCHAPV2_H_)
#define _ABS_EAP_AM_TYPE_MSCHAPV2_H_

#include "eap_type_mschapv2_types.h"

/// This class declares the functions adaptation module of GSMSIM MSCHAPv2 type
/// requires from the MSCHAPv2 EAP type.
class EAP_EXPORT abs_eap_am_type_mschapv2_c
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
	virtual ~abs_eap_am_type_mschapv2_c()
	{
	}

	// 
	abs_eap_am_type_mschapv2_c()
	{
	}

	virtual bool get_is_client() = 0;

	virtual eap_status_e complete_eap_identity_query() = 0;

	virtual eap_status_e complete_failure_retry_response() = 0;

	virtual eap_status_e complete_change_password_query() = 0;

	virtual eap_status_e send_success_failure_response(bool is_success_response) = 0;

	virtual eap_status_e finish_unsuccessful_authentication(
		const bool authentication_cancelled) = 0;

	//--------------------------------------------------
}; // class abs_eap_am_type_mschapv2_c

#endif //#if !defined(_ABS_EAP_AM_TYPE_MSCHAPV2_H_)

//--------------------------------------------------



// End.
