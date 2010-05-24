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
* %version: 13.1.5 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 296 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "EapMsChapV2.h"
#include <e32base.h>
#include <ecom/implementationproxy.h>
#include "EapTraceSymbian.h"

#include "EapolUID.h"

const TImplementationProxy ImplementationTable[] = 
{
	{{EAP_MSCHAPV2_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapMsChapV2::NewL)},
	{{MSCHAPV2_IMPLEMENTATION_UID}, reinterpret_cast<TProxyNewLPtr> (CEapMsChapV2::NewPlainMSCHAPv2L)}
};

// ================= OTHER EXPORTED FUNCTIONS ==============

EXPORT_C const TImplementationProxy* ImplementationGroupProxy(TInt& aTableCount)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("ImplementationGroupProxy(): CEapMsChapV2\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: ImplementationGroupProxy(): CEapMsChapV2\n"));

	aTableCount = sizeof(ImplementationTable) / sizeof(TImplementationProxy);

	return ImplementationTable;
}

// End of file
