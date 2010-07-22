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

#if !defined(_ABS_EAPOL_AM_CORE_SYMBIAN_H_)
#define _ABS_EAPOL_AM_CORE_SYMBIAN_H_

// DATA TYPES
enum TEapIndication {
	EAuthenticating,
	ESuccess,
	ECancelled,
	EFailed,
	ELogoff,
	ENoResponse
};

// CLASS DECLARATION
class abs_eapol_am_core_symbian_c
{
public:

	virtual ~abs_eapol_am_core_symbian_c() {};
	
	virtual TInt EapPacketSend(
		const TUint aBufferLength, 
		const TUint8* const aBuffer) = 0;

	virtual TInt EapIndication(const TEapIndication aIndication) = 0;

	virtual TInt SetWepKey(
		const TUint8* const aKeyData, 
		const TUint aKeyLength, 
		const TUint8 aKeyIndex) = 0;
	
}; 

#endif //#if !defined(_ABS_EAPOL_AM_CORE_SYMBIAN_H_)

//--------------------------------------------------



// End.
