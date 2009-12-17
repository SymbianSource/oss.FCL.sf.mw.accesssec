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


#ifndef _EAPPROTECTEDSETUPINTERFACE_H_
#define _EAPPROTECTEDSETUPINTERFACE_H_

// INCLUDES
#include <e32base.h>
#include "eap_tools.h"

#include <etelmm.h>

// FORWARD DECLARATIONS
class eap_am_type_protected_setup_symbian_c;

// CLASS DECLARATION
/**
* Class (active object) that handles the communications with the 3G SIM.
*/
class CEapProtectedSetupInterface 
: public CActive
{
public:

	// For differentiating the query type.
	enum TQueryType
	{
		EQueryNone,
		EQueryDeviceParams
	};
	
	/**
	* Initialisation function.
	* @param aTools Tools class pointer.
	* @param aParent Pointer to the parent class.
	*/
	static CEapProtectedSetupInterface* NewL(
		abs_eap_am_tools_c* const aTools, 
		eap_am_type_protected_setup_symbian_c* const aParent);	

	/**
	* Destructor
	*/ 
	virtual ~CEapProtectedSetupInterface();

	/**
	* This function queries the device parameters. 
	* After the request has been completed complete_protetced_setup_device_params_L is called in the parent.
	*/
	void QueryDeviceParametersL();

protected:

	CEapProtectedSetupInterface(abs_eap_am_tools_c* const aTools, eap_am_type_protected_setup_symbian_c* const aParent);

	void ConstructL();
	
	void RunL();
	
	void DoCancel();
	
private:
	
	// Creates the MMETel connection and loads the phone module.
	TInt CreateMMETelConnectionL();
	void DisconnectMMETel();	

private:

	eap_am_type_protected_setup_symbian_c * const iParent;
	
	abs_eap_am_tools_c * const m_am_tools;
		
	// ETel connection.
    RTelServer iServer;
    RMobilePhone iPhone;
    
    // Stores the last queried Phone identities like manufacturer, model, 
    // revision and serial number
    RMobilePhone::TMobilePhoneIdentityV1 iDeviceId; 
    
	// Stores the query identifier. Used to check if IMSI query or KC & SRES query.
	TQueryType iQueryId;
	
    // Tells if MMETEL is connected already or not.
    TBool iMMETELConnectionStatus;
	
}; 

#endif // _EAPPROTECTEDSETUPINTERFACE_H_

// End of file
