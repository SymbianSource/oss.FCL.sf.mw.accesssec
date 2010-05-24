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

#if !defined(_EAPOL_AM_CORE_SYMBIAN_WLM_H_)
#define _EAPOL_AM_CORE_SYMBIAN_WLM_H_

// INCLUDES
#include <umacoidmsg.h> // For TMacAddress
#include <wlanmgmtpacket.h> // For MWlanMgmtPacket
#include <EapType.h> // For TIndexType

// FORWARD DECLARATIONS
class abs_eapol_am_core_symbian_c;
class eapol_am_core_symbian_c;

// CLASS DECLARATION

/**
* Class for WLM interface. These are the functions that WLM can call in EAPOL DLL.
* WLM could use eapol_am_core_symbian_c directly but
* that way we would need to export dozens of headers from eapol. This way we need to
* export only a few.
*/
class eapol_am_core_symbian_wlm_c
: public CBase, public MWlanMgmtPacket // From WLM
{
public:
	/**
	* Static constructor.
	*/
	IMPORT_C static eapol_am_core_symbian_wlm_c* NewL(		
		abs_eapol_am_core_symbian_c* const aPartner,
		const bool aIsClient = true);

	/**
	* Destructor.
	*/
	virtual ~eapol_am_core_symbian_wlm_c();	

	/**
	* Processes received EAPOL packets.
	*/
	IMPORT_C TInt ReceivePacket(
		const TUint aLength, 
		const TUint8* const aData);
	/**
	* Starts the sending of EAPOL-Starts.
	*/
	IMPORT_C TInt start_authentication(
		const TIndexType aIndexType, 
		const TUint aIndex,
		const TMacAddress& aLocalAddress, 
		const TMacAddress& aRemoteAddress);	
	/**
	* Resets EAPOL state. Does not actually send EAPOL-Logoff message at the moment. 
	* Note that send_logoff must be called before start_authentication is called again. 
	*/
	IMPORT_C TInt send_logoff(
		const TMacAddress& aLocalAddress, 
		const TMacAddress& aRemoteAddress);	
protected:

	eapol_am_core_symbian_wlm_c();
	
	void ConstructL(
		abs_eapol_am_core_symbian_c* const aPartner, 
		const bool aIsClient);
	
private:
	/// Pointer to next upper stack layer
	eapol_am_core_symbian_c* iEapolCore;

	TBool iLogoffCalled;
	//--------------------------------------------------
};

#endif //#if !defined(_EAPOL_AM_CORE_SYMBIAN_WLM_H_)

//--------------------------------------------------


// End of file
