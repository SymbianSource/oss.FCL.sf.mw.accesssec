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

#if !defined(_ABS_TLS_CHANGE_CIPHER_SPEC_H_)
#define _ABS_TLS_CHANGE_CIPHER_SPEC_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H 
	#define EAP_FUNC_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H 
#elif defined(EAP_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H)
	#define EAP_CLASS_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H 
	#define EAP_C_FUNC_EXPORT_ABS_TLS_CHANGE_CIPHER_SPEC_H 
#endif
// End: added by script change_export_macros.sh.

/// This class declares the functions change cipher spec message class of TLS
/// requires from the TLS.
class EAP_CLASS_VISIBILITY_ABS_TLS_CHANGE_CIPHER_SPEC_H abs_tls_change_cipher_spec_c
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
