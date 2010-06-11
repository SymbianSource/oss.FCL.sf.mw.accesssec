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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 150 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include <e32base.h>
#include "eap_am_memory.h"
#include "eapol_am_core_symbian_wlm.h"
#include "eapol_am_core_symbian.h"

eapol_am_core_symbian_wlm_c::~eapol_am_core_symbian_wlm_c()
{
	delete iEapolCore;
}

eapol_am_core_symbian_wlm_c::eapol_am_core_symbian_wlm_c()
: iEapolCore(0)
, iLogoffCalled(ETrue)
{
}

EXPORT_C eapol_am_core_symbian_wlm_c* eapol_am_core_symbian_wlm_c::NewL(abs_eapol_am_core_symbian_c* const aPartner, const bool aIsClient)
{
	eapol_am_core_symbian_wlm_c* self = new(ELeave) eapol_am_core_symbian_wlm_c;
	CleanupStack::PushL(self);
	self->ConstructL(aPartner, aIsClient);
	CleanupStack::Pop();
	return self;
}

void eapol_am_core_symbian_wlm_c::ConstructL(abs_eapol_am_core_symbian_c* const aPartner,
											 const bool aIsClient)
{
	iEapolCore = eapol_am_core_symbian_c::NewL(aPartner, aIsClient);
}

EXPORT_C TInt eapol_am_core_symbian_wlm_c::ReceivePacket(const TUint aLength, const TUint8* const aData)
{
	return iEapolCore->ReceivePacket(aLength, aData);	
}


EXPORT_C TInt eapol_am_core_symbian_wlm_c::start_authentication(const TIndexType aIndexType,
																const TUint aIndex,
																const TMacAddress& aLocalAddress, 
																const TMacAddress& aRemoteAddress)
{
	__ASSERT_DEBUG(iLogoffCalled, User::Panic(_L("EAPOL"), KErrGeneral));
	iLogoffCalled = EFalse;
	return iEapolCore->start_authentication(aIndexType, aIndex, aLocalAddress, aRemoteAddress);
}

EXPORT_C TInt eapol_am_core_symbian_wlm_c::send_logoff(const TMacAddress& aLocalAddress, 
													   const TMacAddress& aRemoteAddress)
{
	iLogoffCalled = ETrue;
	return iEapolCore->send_logoff(aLocalAddress, aRemoteAddress);
}

// End of file
