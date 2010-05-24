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
* %version: 14.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 420 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "EapTlsPeap.h"
#include <e32base.h>
#include <ecom/implementationproxy.h>

#include "EapolUID.h"

const TImplementationProxy ImplementationTable[] = 
{
	{{EAP_TLS_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapTlsPeap::NewTlsL)},
	{{EAP_PEAP_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapTlsPeap::NewPeapL)},
#if defined(USE_TTLS_EAP_TYPE)
	{{EAP_TTLS_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapTlsPeap::NewTtlsL)}
#endif // #if defined(USE_TTLS_EAP_TYPE)
#if defined(USE_FAST_EAP_TYPE)
	,{{EAP_FAST_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapTlsPeap::NewFastL)}
#endif // #if defined(USE_FAST_EAP_TYPE)
    ,
    {{TTLS_PAP_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapTlsPeap::NewTtlsPapL)}
};

// ================= OTHER EXPORTED FUNCTIONS ==============

EXPORT_C const TImplementationProxy* ImplementationGroupProxy(TInt& aTableCount)
{
	aTableCount = sizeof(ImplementationTable) / sizeof(TImplementationProxy);

	return ImplementationTable;
}

// End of file
