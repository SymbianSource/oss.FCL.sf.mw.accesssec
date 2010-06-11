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

#ifndef ABS_EAP_AM_TYPE_SECURID_H
#define ABS_EAP_AM_TYPE_SECURID_H

#include "eap_status.h"

/// This class declares the functions adaptation module of GSMSIM MSCHAPv2 type
/// requires from the MSCHAPv2 EAP type.
class EAP_EXPORT abs_eap_am_type_securid_c
{
private:

protected:

public:

	virtual ~abs_eap_am_type_securid_c()
	{
	}

	abs_eap_am_type_securid_c()
	{
	}

	virtual bool get_is_client() = 0;

	virtual eap_status_e complete_eap_identity_query(
		const eap_variable_data_c * const identity_utf8) = 0;

	virtual eap_status_e client_securid_complete_passcode_query(
		const eap_variable_data_c * const passcode_utf8) = 0;

	virtual eap_status_e client_securid_complete_pincode_query(
		const eap_variable_data_c * const pincode,
		const eap_variable_data_c * const passcode) = 0;

	virtual eap_status_e client_gtc_complete_user_input_query(
		const eap_variable_data_c * const response_utf8) = 0;

	virtual eap_status_e finish_unsuccessful_authentication(
		const bool authentication_cancelled) = 0;

}; // class abs_eap_am_type_securid_c

#endif // ABS_EAP_AM_TYPE_SECURID_H
