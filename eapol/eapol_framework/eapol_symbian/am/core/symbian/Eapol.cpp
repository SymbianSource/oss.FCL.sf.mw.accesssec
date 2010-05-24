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
	#define EAP_FILE_NUMBER_ENUM 153 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include <e32base.h>
#include "eap_am_memory.h"
#include <Eapol.h>
#include "eapol_am_core_symbian.h"

//--------------------------------------------------

//

CEapol::~CEapol()
{
	delete iEapolCore;
}

//--------------------------------------------------

//

CEapol::CEapol()
: iEapolCore(0)
{
}

//--------------------------------------------------

//

EXPORT_C CEapol* CEapol::NewL(MEapolToWlmIf* const aPartner, const TBool aIsClient, const TUint aServerIndex)
{
	CEapol* self = new(ELeave) CEapol;
	CleanupStack::PushL(self);
	self->ConstructL(aPartner, aIsClient, aServerIndex);
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

//

void CEapol::ConstructL(MEapolToWlmIf* const aPartner, 
						const TBool aIsClient,
						const TUint aServerIndex)
{
	if (aIsClient)
	{
		iEapolCore = eapol_am_core_symbian_c::NewL(aPartner, true, aServerIndex);
	}
	else
	{
		iEapolCore = eapol_am_core_symbian_c::NewL(aPartner, false, aServerIndex);
	}
}

//--------------------------------------------------

//

EXPORT_C TInt CEapol::Start(const TIndexType aIndexType,
							const TUint aIndex,
							const TSSID& aSSID,
							const TBool aWPAOverrideEnabled,
							const TUint8* aWPAPSK,
							const TUint aWPAPSKLength)
{
	return iEapolCore->Start(aIndexType, aIndex, aSSID, aWPAOverrideEnabled, aWPAPSK, aWPAPSKLength);
}

//--------------------------------------------------

//

EXPORT_C TInt CEapol::CompleteAssociation(
	const TInt aResult,
	const TMacAddress& aLocalAddress, 
	const TMacAddress& aRemoteAddress,
	const TUint8* const aReceivedWPAIE, 
	const TUint aReceivedWPAIELength,
	const TUint8* const aSentWPAIE,
	const TUint aSentWPAIELength,
	const TWPACipherSuite aGroupKeyCipherSuite,
	const TWPACipherSuite aPairwiseKeyCipherSuite
	)
{
	return iEapolCore->CompleteAssociation(
		aResult,
		aLocalAddress,
		aRemoteAddress,
		aReceivedWPAIE,
		aReceivedWPAIELength,
		aSentWPAIE,
		aSentWPAIELength,
		aGroupKeyCipherSuite,
		aPairwiseKeyCipherSuite
	);
}

//--------------------------------------------------

//

EXPORT_C TInt CEapol::Disassociated()
{
	return iEapolCore->Disassociated();		
}

//--------------------------------------------------

//

EXPORT_C TInt CEapol::ReceivePacket(const TUint aLength, const TUint8* const aData)
{
	return iEapolCore->ReceivePacket(aLength, aData);	
}

//--------------------------------------------------

//

EXPORT_C TInt CEapol::SendWPAMICFailureReport(
		TBool aFatalMICFailure,
		const TMICFailureType aMICFailureType)
{
	return iEapolCore->SendWPAMICFailureReport(aFatalMICFailure, aMICFailureType);		
}

// End of file
