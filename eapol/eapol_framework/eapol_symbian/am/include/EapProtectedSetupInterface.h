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
* %version: 4.1.3 %
*/

#ifndef _EAPPROTECTEDSETUPINTERFACE_H_
#define _EAPPROTECTEDSETUPINTERFACE_H_

// INCLUDES
#include <e32base.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPPROTECTEDSETUPINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H 
	#define EAP_FUNC_EXPORT_EAPPROTECTEDSETUPINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPPROTECTEDSETUPINTERFACE_H 
#elif defined(EAP_EXPORT_EAPPROTECTEDSETUPINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPPROTECTEDSETUPINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPPROTECTEDSETUPINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPPROTECTEDSETUPINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPPROTECTEDSETUPINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"

#include <etelmm.h>

// FORWARD DECLARATIONS
class CEapAmProtectedSetupSymbian;

// CLASS DECLARATION
/**
* Class (active object) that handles the communications with the 3G SIM.
*/
class EAP_CLASS_VISIBILITY_EAPPROTECTEDSETUPINTERFACE_H CEapProtectedSetupInterface 
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
		CEapAmProtectedSetupSymbian* const aParent);	

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

	CEapProtectedSetupInterface(abs_eap_am_tools_c* const aTools, CEapAmProtectedSetupSymbian* const aParent);

	void ConstructL();
	
	void RunL();
	
	void DoCancel();
	
private:
	
	// Creates the MMETel connection and loads the phone module.
	TInt CreateMMETelConnectionL();
	void DisconnectMMETel();	

private:

	CEapAmProtectedSetupSymbian * const iParent;
	
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
