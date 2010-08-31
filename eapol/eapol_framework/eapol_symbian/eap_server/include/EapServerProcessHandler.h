/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-server process handler.
*
*/

/*
* %version: 22 %
*/


#ifndef EAPPROCESSHANDLER_H_
#define EAPPROCESSHANDLER_H_

#include "EapServerClientDef.h"
#include "AbsEapSendInterface.h"
#include "EapCoreIf.h"
#include "EapPluginIf.h"
#include "EapSettingsIf.h"

#if defined (USE_WAPI_CORE)
#include "WapiCoreIf.h"
#include "WapiSettingsIf.h"
#endif

#if defined(USE_EAP_PAC_STORE_IF)
#include "PacStoreIf.h"
#endif //#if defined(USE_EAP_PAC_STORE_IF)

#include "EapMessageQueue.h"
#include "AbsEapProcessSendInterface.h"

class CEapServerProcessHandler
: public CActive
, public AbsEapSendInterface
{
    
public:
    
	virtual ~CEapServerProcessHandler();

	void ConstructL(AbsEapProcessSendInterface* const client, abs_eap_am_tools_c * const tools);

	static CEapServerProcessHandler* NewL();

	void SaveMessage(TEapRequests message, const void * const data, const TUint length);

	eap_status_e SendData(const void * const data, const u32_t length, TEapRequests message);

	void Activate();

private:

	CEapServerProcessHandler();


	//from CActive

	void DoCancel();
	void RunL();
	TInt RunError(TInt aError);


	AbsEapProcessSendInterface * iClient;
	abs_eap_am_tools_c * iTools;
	CEapCoreIf * iEapCore;
	CEapPluginIf* iEapPlugin;
	CEapSettingsIf* iEapSettings;

#if defined (USE_WAPI_CORE)
	CWapiCoreIf * iWapiCore;
  CWapiSettingsIf* iWapiSettings;
#endif

#if defined(USE_EAP_PAC_STORE_IF) // JPH: does not compile anymore
    CPacStoreIf* iPacStore;
#endif //#if defined(USE_EAP_PAC_STORE_IF) // JPH: does not compile anymore

	EapMessageQueue* iEapMessageQueue;
	

};
    
#endif /* EAPPROCESSHANDLER_H_ */
