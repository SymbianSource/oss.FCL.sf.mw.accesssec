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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 201 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "EapSimSimulatorPlugin.h"
#include "EapSimSimulatorConfig.h"
#include "eap_base_type.h"
#include "eap_am_type_gsmsim_symbian_simulator.h"
#include "eap_type_gsmsim.h"



// ================= MEMBER FUNCTIONS =======================


CEapSimSimulatorPlugin::CEapSimSimulatorPlugin() 
	: iAmEapType(NULL),
	iEapType(NULL),
	iConfig(NULL)
{
}

// ----------------------------------------------------------

CEapSimSimulatorPlugin* CEapSimSimulatorPlugin::NewL()
{
	return new (ELeave) CEapSimSimulatorPlugin;
}

// ----------------------------------------------------------

CEapSimSimulatorPlugin::~CEapSimSimulatorPlugin()
{
	delete iAmEapType;
}

// ----------------------------------------------------------

CEapConfigInterface* CEapSimSimulatorPlugin::CreateConfigIfL(const TIndexType aIndexType, 
													const TInt aIndex)
{
	EAP_UNREFERENCED_PARAMETER(aIndexType);
	EAP_UNREFERENCED_PARAMETER(aIndex);
	return NULL;
}

// ----------------------------------------------------------

eap_base_type_c* CEapSimSimulatorPlugin::CreateTypeIfL(abs_eap_am_tools_c* const aTools, 
										   abs_eap_base_type_c* const aPartner,
										   const bool is_client_when_true,
										   const TIndexType aIndexType,
										   const TInt aIndex)
{
	iAmEapType = new (ELeave) eap_am_type_gsmsim_simulator_c(aTools, aPartner, aIndexType, aIndex);
	iEapType = new (ELeave) eap_type_gsmsim_c(aTools, aPartner, iAmEapType, false /* free_am */, is_client_when_true);
	return iEapType;
}
// End of file
