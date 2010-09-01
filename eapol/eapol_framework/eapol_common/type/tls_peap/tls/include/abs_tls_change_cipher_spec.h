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
* %version: 8 %
*/

#if !defined(_ABS_TLS_CHANGE_CIPHER_SPEC_H_)
#define _ABS_TLS_CHANGE_CIPHER_SPEC_H_

#include "eap_am_export.h"

/// This class declares the functions change cipher spec message class of TLS
/// requires from the TLS.
class EAP_EXPORT abs_tls_change_cipher_spec_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing.
	virtual ~abs_tls_change_cipher_spec_c()
	{
	}

	/// Constructor does nothing.
	abs_tls_change_cipher_spec_c()
	{
	}

	/**
	 * This function indicates the cipher spec must be changed.
	 */
	virtual eap_status_e change_cipher_spec(const bool send_when_true) = 0;

	//--------------------------------------------------
}; // class abs_tls_change_cipher_spec_c

#endif //#if !defined(_ABS_TLS_CHANGE_CIPHER_SPEC_H_)

//--------------------------------------------------



// End.
