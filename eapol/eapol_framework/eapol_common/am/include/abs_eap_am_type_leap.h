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



#ifndef ABS_EAP_AM_TYPE_LEAP_H
#define ABS_EAP_AM_TYPE_LEAP_H

// INCLUDES
#include "eap_type_leap_types.h"

// CLASS DECLARATION

/// This class declares the functions adaptation module of LEAP type
/// requires from the LEAP EAP type.
class EAP_EXPORT abs_eap_am_type_leap_c
{
private:

protected:

public:

	virtual ~abs_eap_am_type_leap_c()
	{
	}

	abs_eap_am_type_leap_c()
	{
	}

	virtual bool get_is_client() = 0;

	virtual eap_status_e complete_eap_identity_query() = 0;

	virtual eap_status_e client_complete_challenge_request() = 0;

	virtual eap_status_e finish_unsuccessful_authentication(
		const bool authentication_cancelled) = 0;

}; // class abs_eap_am_type_leap_c

#endif // ABS_EAP_AM_TYPE_LEAP_H

// End of File
