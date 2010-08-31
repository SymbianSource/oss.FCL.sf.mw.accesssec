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
* %version: 7.1.2 %
*/

#ifndef _EAPSIMPLUGIN_H_
#define _EAPSIMPLUGIN_H_

#include "EapPluginInterface.h"
#include <ecom/implementationproxy.h>

const TUint KVersion = 1;

class CEapSimSimulatorConfiguration;
class eap_type_gsmsim_c;
class eap_am_type_gsmsim_simulator_c;


class CEapSimSimulatorPlugin : public CEapPluginInterface
{
public:		
	CEapSimSimulatorPlugin();
	static CEapSimSimulatorPlugin* NewL();	
	virtual ~CEapSimSimulatorPlugin();
	CEapConfigInterface* CreateConfigIfL(const TIndexType aIndexType, const TInt aIndex);
	eap_base_type_c* CreateTypeIfL(abs_eap_am_tools_c* const aTools, 
								   abs_eap_base_type_c* const aPartner,
								   const bool is_client_when_true,
								   const TIndexType aIndexType,
								   const TInt aIndex);
	TUint GetVersion(void) { return KVersion; };
private:
	CEapSimSimulatorConfiguration* iConfig;
	eap_type_gsmsim_c* iEapType;
	eap_am_type_gsmsim_simulator_c* iAmEapType;
};

const TImplementationProxy ImplementationTable[] = 
{
	{{0x2666666b}, CEapSimSimulatorPlugin::NewL}
};

#endif // _EAPSIMPLUGIN_H_

// End of File
