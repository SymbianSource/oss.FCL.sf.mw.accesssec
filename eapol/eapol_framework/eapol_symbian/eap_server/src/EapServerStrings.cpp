/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 7 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 714
	#undef EAP_FILE_NUMBER_DATE
	#define EAP_FILE_NUMBER_DATE 1127594498
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



/** @file */

#include "EapServerStrings.h"
#include "eap_tools.h"

//------------------------------------------------------------------------------

EXPORT_C EapServerStrings::~EapServerStrings()
{
}

//------------------------------------------------------------------------------

EXPORT_C EapServerStrings::EapServerStrings()
{
}

//------------------------------------------------------------------------------

EXPORT_C eap_const_string EapServerStrings::GetEapRequestsString(const TEapRequests request)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(request, EEapNone)
	else EAP_IF_RETURN_STRING(request, EEapCoreIfNew)
	else EAP_IF_RETURN_STRING(request, EEapPluginNew)
	else EAP_IF_RETURN_STRING(request, EEapSettingsNew)
	else EAP_IF_RETURN_STRING(request, EEapCoreProcessData)
	else EAP_IF_RETURN_STRING(request, EEapPluginProcessData)
	else EAP_IF_RETURN_STRING(request, EEapSettingsProcessData)
	else EAP_IF_RETURN_STRING(request, EEapCoreSendData)
	else EAP_IF_RETURN_STRING(request, EEapPluginSendData)
	else EAP_IF_RETURN_STRING(request, EEapSettingsSendData)
	else EAP_IF_RETURN_STRING(request, EEapIfReqReceive)
	else EAP_IF_RETURN_STRING(request, EEapIfCancelReceive)
	else EAP_IF_RETURN_STRING(request, EEapPacStoreNew)
	else EAP_IF_RETURN_STRING(request, EEapPacStoreProcessData)
	else EAP_IF_RETURN_STRING(request, EEapPacStoreSendData)
	else EAP_IF_RETURN_STRING(request, EWapiCoreIfNew)
	else EAP_IF_RETURN_STRING(request, EWapiSettingsNew)
	else EAP_IF_RETURN_STRING(request, EWapiCoreProcessData)
	else EAP_IF_RETURN_STRING(request, EWapiSettingsProcessData)
	else EAP_IF_RETURN_STRING(request, EWapiCoreSendData)
	else EAP_IF_RETURN_STRING(request, EWapiSettingsSendData)

	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(request);
		return EAPL("Unknown TEapRequests");
	}

}

//------------------------------------------------------------------------------

EXPORT_C eap_const_string EapServerStrings::GetEapRequestsString(const TInt request)
{
	return EapServerStrings::GetEapRequestsString(static_cast<TEapRequests>(request));
}

//------------------------------------------------------------------------------
// End.
