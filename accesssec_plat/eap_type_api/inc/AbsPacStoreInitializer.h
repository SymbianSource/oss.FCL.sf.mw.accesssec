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
* %version: 2 %
*/

#if !defined(_ABSPACSTOREINITIALIZER_H_)
#define _ABSPACSTOREINITIALIZER_H_

#if defined(USE_FAST_EAP_TYPE)
	#include "eap_fast_types.h"
#endif //#if defined(USE_FAST_EAP_TYPE)
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABSPACSTOREINITIALIZER_H)
	#define EAP_CLASS_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABSPACSTOREINITIALIZER_H 
	#define EAP_C_FUNC_VISIBILITY_ABSPACSTOREINITIALIZER_H 
	#define EAP_FUNC_EXPORT_ABSPACSTOREINITIALIZER_H 
	#define EAP_C_FUNC_EXPORT_ABSPACSTOREINITIALIZER_H 
#elif defined(EAP_EXPORT_ABSPACSTOREINITIALIZER_H)
	#define EAP_CLASS_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABSPACSTOREINITIALIZER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABSPACSTOREINITIALIZER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABSPACSTOREINITIALIZER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABSPACSTOREINITIALIZER_H 
	#define EAP_C_FUNC_EXPORT_ABSPACSTOREINITIALIZER_H 
#endif
// End: added by script change_export_macros.sh.


/// The class is the interface to partner class of the tls_base_application_c class which starts the PAC-store initialization.
/// This declares the pure virtual member functions tls_base_application_c class could call.
class EAP_CLASS_VISIBILITY_ABSPACSTOREINITIALIZER_H AbsPacStoreInitializer
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the AbsPacStoreInitializer class does nothing special.
	 */
	virtual ~AbsPacStoreInitializer()
	{
	}

	/**
	 * The constructor of the AbsPacStoreInitializer class does nothing special.
	 */
	AbsPacStoreInitializer()
	{
	}

#if defined(USE_FAST_EAP_TYPE)

	virtual TInt CompleteInitialisePacStore() = 0;

#endif //#if defined(USE_FAST_EAP_TYPE)

	//--------------------------------------------------
}; // class AbsPacStoreInitializer

#endif //#if !defined(_ABSPACSTOREINITIALIZER_H_)

//--------------------------------------------------

// End.
