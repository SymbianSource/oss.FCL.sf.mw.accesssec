/*
* Copyright (c) 2007 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP stack interface for Wimax.
*
*/

/*
* %version: %
*/

#if !defined(_ABS_EAP_AM_WIMAX_AUTHENTICATION_H_)
#define _ABS_EAP_AM_WIMAX_AUTHENTICATION_H_

#include <eap_am_export.h>
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_WIMAX_AUTHENTICATION_H 
#endif
// End: added by script change_export_macros.sh.
#include <eapol_key_types.h>


class EAP_CLASS_VISIBILITY_ABS_EAP_AM_WIMAX_AUTHENTICATION_H abs_eap_am_wimax_authentication_c
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
	virtual ~abs_eap_am_wimax_authentication_c()
	{
	}

	// 
	abs_eap_am_wimax_authentication_c()
	{
	}

	//--------------------------------------------------
}; // class abs_eap_am_wimax_authentication_c

#endif //#if !defined(_ABS_EAP_AM_WIMAX_AUTHENTICATION_H_)

//--------------------------------------------------



// End.

