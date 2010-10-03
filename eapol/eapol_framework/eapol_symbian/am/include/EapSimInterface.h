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
* %version: 9.1.4 %
*/

#ifndef _EAPSIMINTERFACE_H_
#define _EAPSIMINTERFACE_H_

// INCLUDES
#include <e32base.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPSIMINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPSIMINTERFACE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPSIMINTERFACE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPSIMINTERFACE_H 
	#define EAP_FUNC_EXPORT_EAPSIMINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPSIMINTERFACE_H 
#elif defined(EAP_EXPORT_EAPSIMINTERFACE_H)
	#define EAP_CLASS_VISIBILITY_EAPSIMINTERFACE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPSIMINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPSIMINTERFACE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPSIMINTERFACE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPSIMINTERFACE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPSIMINTERFACE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPSIMINTERFACE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPSIMINTERFACE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPSIMINTERFACE_H 
	#define EAP_C_FUNC_EXPORT_EAPSIMINTERFACE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"
#include "eap_am_type_gsmsim_symbian.h"

#include <etelmm.h>
#include <rmmcustomapi.h>

// CLASS DECLARATION
/**
* Class (active object) that handles the communications with the SIM.
*/
class EAP_CLASS_VISIBILITY_EAPSIMINTERFACE_H CEapSimIsaInterface 
: public CActive
{
public:

	// For differentiating the query type.
	enum TQueryType
	{
		EQueryNone,
		EQueryIMSI,
		EQuerySRESandKC
	};
	/**
	* Initialisation function.
	* @param aTools Tools class pointer.
	* @param aParent Pointer to the parent class.
	*/
	static CEapSimIsaInterface* NewL(
		abs_eap_am_tools_c* const aTools, 
		eap_am_type_gsmsim_symbian_c* const aParent);	

	/**
	* Destructor
	*/ 
	virtual ~CEapSimIsaInterface();

	/**
	* This function queries the IMSI from SIM. After the request has been completed
	* complete_SIM_imsi is called in the parent.
	*/
	void QueryIMSIL();

	/**
	* This function queries Kc and SRES from SIM. After the request has been completed
	* complete_SIM_kc_and_sres is called in the parent.
	* @param aRand Random value
	*/
	void QueryKcAndSRESL(const TDesC8& aRand);

protected:

	CEapSimIsaInterface(abs_eap_am_tools_c* const aTools, eap_am_type_gsmsim_symbian_c* const aParent);

	void ConstructL();
	
	void RunL();
	
	void DoCancel();
	
private:
	
	// Creates the MMETel connection and loads the phone module.
	TInt CreateMMETelConnectionL();

	void DisconnectMMETel();

private:

	eap_am_type_gsmsim_symbian_c * const iParent;
	
	abs_eap_am_tools_c * const m_am_tools;
		
	// ETel connection.
    RTelServer iServer;
    RMobilePhone iPhone;
    
    //For custom API.
    RMmCustomAPI iCustomAPI;  
    
    // Stores the last queried Subscriber Id ( IMSI ).
    RMobilePhone::TMobilePhoneSubscriberId iSubscriberId; 
    
    // Stores the SIM authentication details.
	RMmCustomAPI::TSimAuthenticationEapSim iEAPSim;
	
	// For the packaged authentication data.
	RMmCustomAPI::TSimDataPckg *iAuthenticationData;
	
	// Stores the query identifier. Used to check if IMSI query or KC & SRES query.
	TQueryType iQueryId;
	
    // Tells if MMETEL is connected already or not.
    TBool iMMETELConnectionStatus;
	
}; 

#endif // _EAPSIMINTERFACE_H_

// End of file
