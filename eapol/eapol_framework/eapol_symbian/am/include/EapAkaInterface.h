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


#ifndef _EAPAKAINTERFACE_H_
#define _EAPAKAINTERFACE_H_

// INCLUDES
#include <e32base.h>
#include "eap_tools.h"
#include "eap_am_type_aka_symbian.h"

#include <etelmm.h>
#include <rmmcustomapi.h>

// CLASS DECLARATION
/**
* Class (active object) that handles the communications with the 3G SIM.
*/
class CEapAkaInterface 
: public CActive
{
public:

	// For differentiating the query type.
	enum TQueryType
	{
		EQueryNone,
		EQueryIMSI,
		EQueryRES
	};
	/**
	* Initialisation function.
	* @param aTools Tools class pointer.
	* @param aParent Pointer to the parent class.
	*/
	static CEapAkaInterface* NewL(
		abs_eap_am_tools_c* const aTools, 
		eap_am_type_aka_symbian_c* const aParent);	

	/**
	* Destructor
	*/ 
	virtual ~CEapAkaInterface();

	/**
	* This function queries the IMSI from 3G SIM. After the request has been completed
	* complete_SIM_imsi is called in the parent.
	*/
	void QueryIMSIL();

	/**
	* This function queries RES, CK, IK and AUTS from 3G SIM. After the request has been completed
	* complete_AKA_RES_L is called in the parent.
	* @param aRand Random value
	* @param aAUTN Authentication Token
	*/
	void QueryRESL( eap_variable_data_c * const aRand, eap_variable_data_c * const aAUTN );

protected:

	CEapAkaInterface(abs_eap_am_tools_c* const aTools, eap_am_type_aka_symbian_c* const aParent);

	void ConstructL();
	
	void RunL();
	
	void DoCancel();
	
private:
	
	// Creates the MMETel connection and loads the phone module.
	TInt CreateMMETelConnectionL();
	void DisconnectMMETel();	

private:

	eap_am_type_aka_symbian_c * const iParent;
	
	abs_eap_am_tools_c * const m_am_tools;
		
	// ETel connection.
    RTelServer iServer;
    RMobilePhone iPhone;
    
    //For custom API.
    RMmCustomAPI iCustomAPI;  
    
    // Stores the last queried Subscriber Id ( IMSI ).
    RMobilePhone::TMobilePhoneSubscriberId iSubscriberId; 
    
    // Stores the SIM authentication details.
	RMmCustomAPI::TSimAuthenticationEapAka iEAPAka;
	
	// For the packaged authentication data.
	RMmCustomAPI::TAkaDataPckg *iAuthenticationData;
	
	// Stores the query identifier. Used to check if IMSI query or KC & SRES query.
	TQueryType iQueryId;
	
    // Tells if MMETEL is connected already or not.
    TBool iMMETELConnectionStatus;
	
}; 

#endif // _EAPAKAINTERFACE_H_

// End of file
