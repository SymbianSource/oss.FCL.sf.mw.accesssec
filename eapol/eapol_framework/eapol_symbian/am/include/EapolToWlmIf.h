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

#if !defined(_EAPOLTOWLMIF_H_)
#define _EAPOLTOWLMIF_H_

#include <umacoidmsg.h>

// DATA TYPES

// These are the possible indications EAPOL can send to WLM.
enum TEapIndication {
	EAuthenticating,
	ESuccess,
	EThisAPFailed, // This AP failed all EAP types. Next AP could be better.
	EFailedCompletely, // Configuration failure or something else fatal. 
					   // No point trying other APs.	
	ENoResponse,
	ELeapSuccess // Indicates that EAP-LEAP protocol succeeded. 
				 // This means that rogue AP results must be sent.
};

// The possible rogue AP values
enum TRogueType {
	EInvalidAuthenticationType = 1, 
	EAuthenticationTimeout,
	EChallengeFromAPFailed, 
	EChallengeToAPFailed
};

// Possible cipher suites
// RC4 keys are used in WEP, TKIP and CKIP cipher suites.
enum TCipherKeyType {
	ERC4Unicast,
	ERC4Broadcast
};

// CLASS DECLARATION
class MEapolToWlmIf
{
public:	
	
	/**
	* Associates the an access point using the specified authentication mode.
	* @param aAuthenticationMode Authentication mode (open, shared, LEAP)
	* @return TInt result
	*/
	virtual TInt Associate(TAuthenticationMode aAuthenticationMode) = 0;
	
	/**
	* Disassociates from an access point.	
	* @return TInt result
	*/	
	virtual TInt Disassociate() = 0;
	
	/**
	* Sends an EAP packet.
	* @param aBufferLength Packet length
	* @param aBuffer Packet data
	* @return TInt result
	*/	
	virtual TInt EapPacketSend(
		const TUint aBufferLength, 
		const TUint8* const aBuffer) = 0;

	/**
	* Indication of some event from EAPOL to WLM.
	* @param aIndication Event code	
	* @return TInt result
	*/		
	virtual TInt EapIndication(const TEapIndication aIndication) = 0;

	/**
	* Sets the cipher key. When EAPOL has finished authentication it generates cipher keys and
	* uses this function to send them to WLM and drivers.
	* @param aKeyType Type of the key to be set.
	* @param aKeyIndex Index for the key (if applicable)
	* @param aKeyData Key data
	* @param aKeyLength	Key Length
	* @return TInt result
	*/		
	virtual TInt SetCipherKey(
		const TCipherKeyType aKeyType,
		const TUint8 aKeyIndex,
		const TUint8* const aKeyData, 
		const TUint aKeyLength		
		) = 0;	

	/**
	* Report the current AP to be rogue. This happens when LEAP authentication 
	* fails for some reason
	* @param aAddress Address of the rogue AP
	* @param aRogueType Indicates the type of the failure.		
	* @return TInt result
	*/		
	virtual TInt AddRogueAP(
		const TMacAddress& aAddress, 
		const TRogueType aRogueType) = 0;
}; 

#endif //#if !defined(_EAPOLTOWLMIF_H_)

//--------------------------------------------------



// End.
