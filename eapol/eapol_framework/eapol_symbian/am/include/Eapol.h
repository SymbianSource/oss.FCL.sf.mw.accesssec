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

#if !defined(_EAPOL_H_)
#define _EAPOL_H_

// INCLUDES
#include <umacoidmsg.h> // For TMacAddress
#include <wlanmgmtpacket.h> // For MWlanMgmtPacket
#include <EapType.h> // For TIndexType

// DATA TYPES
enum TWPACipherSuite {
	ENoCipherSuite,   // Unsupported
	EWEP40,    // TBC: Unsupported	
	EWEP104,
	ETKIP,
	ECCMP,	 // Unsupported
	EWRAP    // Unsupported
};

enum TMICFailureType {
	EGroupKey,
	EPairwiseKey	
};

// FORWARD DECLARATIONS
class eapol_am_core_symbian_c;
class MEapolToWlmIf;

// CLASS DECLARATION

/**
* Class for WLM interface. These are the functions that WLM can call in EAPOL DLL.
* WLM could use eapol_am_core_symbian_c directly but
* that way we would need to export dozens of headers from eapol. This way we need to
* export only a few.
*/
class CEapol
: public CBase, public MWlanMgmtPacket // From WLM
{
public:
	/**
	* Static constructor.
	* @param aPartner Pointer to creator of this class
	* @param aIsClient Specifies whether this EAPOL instance will 
	*                  act as a client or server
	* @return Pointer to instantiated class
	*/
	IMPORT_C static CEapol* NewL(		
		MEapolToWlmIf* const aPartner,
		const TBool aIsClient = ETrue,
		const TUint aServerIndex = 0);

	/**
	* Destructor.
	*/
	virtual ~CEapol();	

	/**
	* Starts the authentication process. After this is called EAPOL 
	* reads IAP configuration and starts associations.
	* @param aIndexType IAP index type
	* @param aIndex IAP index
	* @param aSSID SSID of the network
	* @param aWPAOverrideEnabled State whether WPA override is active (used with Easy WLAN)
	* @param aWPAPSK WPA PSK override (used with Easy WLAN)
	* @param aWPAPSKLength WPA PSK override length
	* @return TInt result
	*/
	IMPORT_C TInt Start( // Non-Leaving functions OK for WLM?
		const TIndexType aIndexType, 
		const TUint aIndex,
		const TSSID& aSSID,
		const TBool aWPAOverrideEnabled,
		const TUint8* aWPAPSK,
		const TUint aWPAPSKLength
		);
	/**
	* Called by WLM when association has been done (or failed). 
	* After this is called EAPOL starts sending EAPOL-starts.
	* @param aResult Result code indicating whether association was successful
	* @param aLocalAddress Local MAC address
	* @param aRemoteAddress Remote MAC address
	* @param aReceivedWPAIE WPA IE received from the AP if available (NULL otherwise).
	* @param aReceivedWPAIELength Received WPA IE length.
	* @param aSentWPAIE WPA IE sent to the AP if available (NULL otherwise).
	* @param aSentWPAIELength Sent WPA IE length.
	* @param aGroupKeyCipherSuite If security mode is WPA then this is the used
	*		                      group key cipher suite.
	* @param aPairwiseKeyCipherSuite If security mode is WPA then this is the used
	*		                         pairwise key cipher suite. 
	* @return TInt result
	*/
	IMPORT_C TInt CompleteAssociation(
		const TInt aResult,
		const TMacAddress& aLocalAddress, 
		const TMacAddress& aRemoteAddress,
		const TUint8* const aReceivedWPAIE, // WLM must give only the WPA IE to EAPOL									        
		const TUint aReceivedWPAIELength,
		const TUint8* const aSentWPAIE,
		const TUint aSentWPAIELength,
		const TWPACipherSuite aGroupKeyCipherSuite,
		const TWPACipherSuite aPairwiseKeyCipherSuite
		);		

	/**
	* Indicates that we have disassociated from the AP. 	
	* This causes EAPOL to stop everything it is doing and go to idle state. 
	* @return TInt result
	*/
	IMPORT_C TInt Disassociated(); 
		
	/**
	* Processes received EAPOL packets.
	* @param aLength Packet length
	* @param aData Packet data
	* @return TInt result
	*/
	IMPORT_C TInt ReceivePacket(
		const TUint aLength, 
		const TUint8* const aData);

	/**
	* Sends WPA MIC failure report. 
	* @param aFatalMICFailure Flag indicating if this is the second MIC failure 
	*                         in 60 seconds.
	* @param aMICFailureType Indicates whether the failure occurred in pairwise or
	*                        group key decoding.
	* @return TInt result
	*/
	IMPORT_C TInt SendWPAMICFailureReport(
		TBool aFatalMICFailure,
		const TMICFailureType aMICFailureType); 

protected:

	CEapol();
	
	void ConstructL(
		MEapolToWlmIf* const aPartner, 
		const TBool aIsClient,
		const TUint aServerIndex);
	
private:

	/// Pointer to next upper stack layer
	eapol_am_core_symbian_c* iEapolCore;
	//--------------------------------------------------
};

#endif //#if !defined(_EAPOL_H_)

//--------------------------------------------------


// End of file
