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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version:  39 %
*/

#include "EapServerProcessHandler.h"
#include "EapTraceSymbian.h"
#if defined(USE_FAST_EAP_TYPE)
#include "PacStoreIf.h"
#endif //#if defined(USE_FAST_EAP_TYPE)
#include "EapServerStrings.h"
#include "eap_automatic_variable.h"

//----------------------------------------------------------------------------

CEapServerProcessHandler::CEapServerProcessHandler()
: CActive (0)
, iClient(0)
, iTools(0)
, iEapCore(0)
, iEapPlugin(0)
, iEapSettings(0)
#if defined (USE_WAPI_CORE)
, iWapiCore(0)
, iWapiSettings(0)
#endif
#if defined(USE_FAST_EAP_TYPE)
, iPacStore(0)
#endif //#if defined(USE_FAST_EAP_TYPE)
, iEapMessageQueue(0)
{

}

//----------------------------------------------------------------------------

CEapServerProcessHandler::~CEapServerProcessHandler()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::~CEapServerProcessHandler(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::~CEapServerProcessHandler()");

	if(IsActive())
	{
		Cancel();
	}

	delete iEapCore;
	iEapCore = 0;

	delete iEapPlugin;
	iEapPlugin = 0;

	delete iEapSettings;
	iEapSettings = 0;

#if defined (USE_WAPI_CORE)
    delete iWapiCore;
    iWapiCore = 0;

    delete iWapiSettings;
    iWapiSettings = 0;
#endif

#if defined(USE_FAST_EAP_TYPE)
    delete iPacStore;
    iPacStore = 0;
#endif //#if defined(USE_FAST_EAP_TYPE)

    delete iEapMessageQueue;
	iEapMessageQueue = 0;
}
    
//----------------------------------------------------------------------------

CEapServerProcessHandler* CEapServerProcessHandler::NewL()
{
	return new (ELeave) CEapServerProcessHandler();
}

//----------------------------------------------------------------------------

void CEapServerProcessHandler::ConstructL(AbsEapProcessSendInterface* const client, abs_eap_am_tools_c * const tools)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::ConstructL(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(tools, "returns: CEapServerProcessHandler::ConstructL()");

	iClient = client;
	iTools = tools;

	iEapMessageQueue = new(ELeave) EapMessageQueue(iTools);
}

//----------------------------------------------------------------------------

eap_status_e CEapServerProcessHandler::SendData(const void * const data, const u32_t length, TEapRequests message)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::SendData(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::SendData()");

	eap_status_e status(eap_status_ok);

	SaveMessage(message, data, length);

	return status;
}

//----------------------------------------------------------------------------

void CEapServerProcessHandler::SaveMessage(TEapRequests message, const void * const data, const TUint length)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::SaveMessage(): this=0x%08x, message=%d=%s\n"),
		this,
		message,
		EapServerStrings::GetEapRequestsString(message)));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::SaveMessage()");

	EAP_TRACE_DATA_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::SaveMessage()"),
		data,
		length));

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::SaveMessage(): calls iEapMessageQueue->AddMessage()\n")));

	TInt error = iEapMessageQueue->AddMessage(message, data, length);

	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CEapServerProcessHandler::SaveMessage(): failed = %d\n"),
			error));
		return;
	}

	Activate();

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::SaveMessage(): returns this=0x%08x, message=%d=%s\n"),
		this,
		message,
		EapServerStrings::GetEapRequestsString(message)));
}

//----------------------------------------------------------------------------

void CEapServerProcessHandler::Activate()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::Activate(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::Activate()");

	if(!IsActive())
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServerProcessHandler::Activate(): calls User::RequestComplete()\n")));

		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServerProcessHandler::Activate(): calls SetActive()\n")));

		SetActive();
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServerProcessHandler::Activate(): Already active.\n")));
	}
}

//----------------------------------------------------------------------------

void CEapServerProcessHandler::RunL()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("=start=====================================================================\n")));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::RunL()");

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::RunL(): this=0x%08x\n"),
		this));

	EapMessageBuffer * const message = iEapMessageQueue->GetFirstMessage();

	if (message != 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServerProcessHandler::RunL(): message->GetRequestType()=%d=%s, data=0x%08x, size=%d\n"),
			message->GetRequestType(),
			EapServerStrings::GetEapRequestsString(message->GetRequestType()),
			message->GetData()->Ptr(),
			message->GetData()->Size()));

		eap_status_e status(eap_status_ok);

		switch (message->GetRequestType())
		{

		case EEapCoreIfNew:

			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapCoreIfNew\n")));

				CEapCoreIf * tmpEapCore = CEapCoreIf::new_CEapCoreIf(
					iTools,
					ETrue,
					0,
					this);

				if (tmpEapCore != 0)
				{
					CleanupStack::PushL(tmpEapCore);

					if (tmpEapCore->get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): CEapCoreIf::new_CEapCoreIf() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					const void * const aData = reinterpret_cast<const void *>(message->GetData()->Ptr());
					const TInt aLength = message->GetData()->Size();

					const eap_variable_data_c client_configuration(
						iTools,
						aData,
						aLength,
						false,
						false);
					if (client_configuration.get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): eap_variable_data_c client_configuration() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					status = tmpEapCore->configure(&client_configuration);
					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): tmpEapCore->configure() failed, this=0x%08x, status=%d=%s\n"),
							this,
							status,
							eap_status_string_c::get_status_string(status)));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
					}

					iEapCore = tmpEapCore;

					CleanupStack::Pop(tmpEapCore);
				}
				else
				{
					EAP_TRACE_DEBUG(
						iTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapCoreIfNew, iEapCore is NULL\n")));
				}
			}

			break;

		case EEapPluginNew:

			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapPluginNew\n")));

				CEapPluginIf * tmpEapPlugin = CEapPluginIf::new_CEapPluginIf(iTools);

				if (tmpEapPlugin != 0)
				{
					CleanupStack::PushL(tmpEapPlugin);

					if (tmpEapPlugin->get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): CEapPluginIf::new_CEapPluginIf() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					tmpEapPlugin->set_partner(this);

					const void * const aData = reinterpret_cast<const void *>(message->GetData()->Ptr());
					const TInt aLength = message->GetData()->Size();

					const eap_variable_data_c client_configuration(
						iTools,
						aData,
						aLength,
						false,
						false);
					if (client_configuration.get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): eap_variable_data_c client_configuration() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					status = tmpEapPlugin->configure(&client_configuration);
					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): tmpEapPlugin->configure() failed, this=0x%08x, status=%d=%s\n"),
							this,
							status,
							eap_status_string_c::get_status_string(status)));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
					}

					iEapPlugin = tmpEapPlugin;

					CleanupStack::Pop(tmpEapPlugin);
				}
				else
				{
					EAP_TRACE_DEBUG(
						iTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapPluginNew, iEapPlugin is NULL\n")));
				}
			}

			break;

		case EEapSettingsNew:

			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapSettingsNew\n")));

				CEapSettingsIf * tmpEapSettings = CEapSettingsIf::new_CEapSettingsIf(iTools);

				if (tmpEapSettings != 0)
				{
					CleanupStack::PushL(tmpEapSettings);

					if (tmpEapSettings->get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): CEapSettingsIf::new_CEapSettingsIf() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					tmpEapSettings->set_partner(this);

					const void * const aData = reinterpret_cast<const void *>(message->GetData()->Ptr());
					const TInt aLength = message->GetData()->Size();

					const eap_variable_data_c client_configuration(
						iTools,
						aData,
						aLength,
						false,
						false);
					if (client_configuration.get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): eap_variable_data_c client_configuration() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					status = tmpEapSettings->configure(&client_configuration);
					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): tmpEapSettings->configure() failed, this=0x%08x, status=%d=%s\n"),
							this,
							status,
							eap_status_string_c::get_status_string(status)));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
					}

					iEapSettings = tmpEapSettings;

					CleanupStack::Pop(tmpEapSettings);
				}
				else
				{
					EAP_TRACE_DEBUG(
						iTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapSettingsNew, iEapSettings is NULL\n")));
				}
			}

			break;

#if defined (USE_WAPI_CORE)
	     case EWapiCoreIfNew:

	            EAP_TRACE_DEBUG(
	                iTools,
	                TRACE_FLAGS_DEFAULT,
	                (EAPL("CEapServerProcessHandler::RunL() EWapiCoreIfNew\n")));

                iWapiCore = CWapiCoreIf::NewL(iTools, this);

				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EWapiCoreIfNew - iWapiCore = 0x%08x.\n"),
					iWapiCore));


	            break;

	        case EWapiSettingsNew:

	            EAP_TRACE_DEBUG(
	                iTools,
	                TRACE_FLAGS_DEFAULT,
	                (EAPL("CEapServerProcessHandler::RunL() EWapiSettingsNew\n")));

	            iWapiSettings = CWapiSettingsIf::NewL(iTools, this);

				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EWapiSettingsNew - iWapiSettings = 0x%08x.\n"),
					iWapiSettings));
	            break;
#endif
	            
        case EEapPacStoreNew:

			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapPacStoreNew\n")));

#if defined(USE_FAST_EAP_TYPE)

				CPacStoreIf * tmpPacStore = CPacStoreIf::new_CPacStoreIf(
					iTools,
					ETrue,
					0,
					this);

				if (tmpPacStore != 0)
				{
					CleanupStack::PushL(tmpPacStore);

					if (tmpPacStore->get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): CPacStoreIf::new_CPacStoreIf() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					const void * const aData = reinterpret_cast<const void *>(message->GetData()->Ptr());
					const TInt aLength = message->GetData()->Size();

					const eap_variable_data_c client_configuration(
						iTools,
						aData,
						aLength,
						false,
						false);
					if (client_configuration.get_is_valid() == false)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): eap_variable_data_c client_configuration() failed, this=0x%08x\n"),
							this));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, eap_status_allocation_error)));
					}

					status = tmpPacStore->configure(&client_configuration);
					if (status != eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							iTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CEapServerProcessHandler::RunL(): tmpPacStore->configure() failed, this=0x%08x, status=%d=%s\n"),
							this,
							status,
							eap_status_string_c::get_status_string(status)));

						User::Leave(iTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iTools, status)));
					}

					iPacStore = tmpPacStore;

					CleanupStack::Pop(tmpPacStore);
				}
				else
				{
					EAP_TRACE_DEBUG(
						iTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapPacStoreNew, iPacStore is NULL\n")));
				}

#endif //#if defined(USE_FAST_EAP_TYPE)

			}

            break;

        case EEapCoreProcessData:

            EAP_TRACE_DEBUG(
                iTools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("CEapServerProcessHandler::RunL() EEapCoreProcessData\n")));

            if (iEapCore !=0)
            {
                void* aData = reinterpret_cast<void *>(const_cast<TUint8 *>(message->GetData()->Ptr()));
                TInt aLength = message->GetData()->Size();
                iEapCore->process_data(aData, aLength);
            }
            else
            {
                EAP_TRACE_DEBUG(
                    iTools,
                    TRACE_FLAGS_DEFAULT,
                    (EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapCoreProcessData, iEapCore is NULL\n")));
            }

            break;

        case EEapPacStoreProcessData:

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServerProcessHandler::RunL() EEapPacStoreProcessData\n")));

#if defined(USE_FAST_EAP_TYPE)
			if (iPacStore !=0)
			{
				void* aData = reinterpret_cast<void *>(const_cast<TUint8 *>(message->GetData()->Ptr()));
				TInt aLength = message->GetData()->Size();
				iPacStore->process_data(aData, aLength);
			}
			else
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapPacStoreProcessData, iPacStore is NULL\n")));
			}
#endif //#if defined(USE_FAST_EAP_TYPE)
			break;

		case EEapPluginProcessData:

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServerProcessHandler::RunL() EEapPluginProcessData\n")));

			if (iEapPlugin !=0)
			{
				void* aData = reinterpret_cast<void *>(const_cast<TUint8 *>(message->GetData()->Ptr()));
				TInt aLength = message->GetData()->Size();
				iEapPlugin->process_data(aData, aLength);
			}
			else
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapPluginProcessData, iEapPlugin is NULL\n")));
			}

			break;

		case EEapSettingsProcessData:

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServerProcessHandler::RunL() EEapSettingsProcessData\n")));

			if (iEapSettings !=0)
			{
				void* aData = reinterpret_cast<void *>(const_cast<TUint8 *>(message->GetData()->Ptr()));
				TInt aLength = message->GetData()->Size();
				iEapSettings->process_data(aData, aLength);
			}
			else
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEapSettingsProcessData, iEapSettings is NULL\n")));
			}

			break;

#if defined (USE_WAPI_CORE)
		case EWapiCoreProcessData:

            EAP_TRACE_DEBUG(
                iTools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("CEapServerProcessHandler::RunL() EWapiCoreProcessData\n")));

            if (iWapiCore !=0)
            {
                void* aData = reinterpret_cast<void *>(const_cast<TUint8 *>(message->GetData()->Ptr()));
                TInt aLength = message->GetData()->Size();
                iWapiCore->process_data(aData, aLength);
            }
            else
            {
                EAP_TRACE_DEBUG(
                    iTools,
                    TRACE_FLAGS_DEFAULT,
                    (EAPL("ERROR: CEapServerProcessHandler::RunL(): EWapiCoreProcessData, iWapiCore is NULL\n")));
            }
            break;

		case EWapiSettingsProcessData:

            EAP_TRACE_DEBUG(
                iTools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("CEapServerProcessHandler::RunL() EWapiSettingsProcessData\n")));

            if (iWapiSettings !=0)
            {
                void* aData = reinterpret_cast<void *>(const_cast<TUint8 *>(message->GetData()->Ptr()));
                TInt aLength = message->GetData()->Size();
                iWapiSettings->process_data(aData, aLength);
            }
            else
            {
                EAP_TRACE_DEBUG(
                    iTools,
                    TRACE_FLAGS_DEFAULT,
                    (EAPL("ERROR: CEapServerProcessHandler::RunL(): EWapiSettingsProcessData, iWapiSettings is NULL\n")));
            }

            break;
#endif

		case EEapCoreSendData:
		case EEapPluginSendData:
		case EEapSettingsSendData:
        case EEapPacStoreSendData:
#if defined (USE_WAPI_CORE)
        case EWapiCoreSendData:
        case EWapiSettingsSendData:
#endif
			if (message->GetRequestType() == EEapCoreSendData)
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapCoreSendData\n")));
			}
			else if (message->GetRequestType() == EEapPluginSendData)
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapPluginSendData\n")));
			}
			else if (message->GetRequestType() == EEapSettingsSendData)
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapServerProcessHandler::RunL() EEapSettingsSendData\n")));
			}
            else if (message->GetRequestType() == EEapPacStoreSendData)
            {
                EAP_TRACE_DEBUG(
                    iTools,
                    TRACE_FLAGS_DEFAULT,
                    (EAPL("CEapServerProcessHandler::RunL() EEapPacStoreSendData\n")));
            }
#if defined (USE_WAPI_CORE)
            else if (message->GetRequestType() == EWapiCoreSendData)
            {
                EAP_TRACE_DEBUG(
                    iTools,
                    TRACE_FLAGS_DEFAULT,
                    (EAPL("CEapServerProcessHandler::RunL() EWapiCoreSendData\n")));
            }
            else if (message->GetRequestType() == EWapiSettingsSendData)
            {
                EAP_TRACE_DEBUG(
                    iTools,
                    TRACE_FLAGS_DEFAULT,
                    (EAPL("CEapServerProcessHandler::RunL() EWapiSettingsSendData\n")));
            }
#endif
			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapServerProcessHandler::RunL(): iClient=0x%08x\n"),
				iClient));

			if (iClient != 0)
			{
				status = iClient->SendData(message);
				if (status != eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						iTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: CEapServerProcessHandler::RunL(): SendData() failed, iClient=0x%08x, status=%d=%s\n"),
						iClient,
						status,
						eap_status_string_c::get_status_string(status)));

					// We do not return here. Even the iClient->SendData() fails we run this function to the end.
				}
			}
			else
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: CEapServerProcessHandler::RunL(): EEap*SendData, iClient is NULL\n")));
			}

			break;

		default:

			EAP_TRACE_DEBUG(
				iTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapServerProcessHandler::RunL(): unknown message->GetRequestType()=%d=%s\n"),
				message->GetRequestType(),
				EapServerStrings::GetEapRequestsString(message->GetRequestType())));
			break;

		} // switch()

		if (status == eap_status_ok)
		{
			// First one handled, remove message.
			// iClient->SendData() call may fail, then we do not remove the message.
			iEapMessageQueue->DeleteFirstMessage();
		}

	} // if ()

	if (iEapMessageQueue->GetFirstMessage() != 0)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServerProcessHandler::RunL(): Still messages waiting.\n")));

		if (iClient != NULL)
		{
			if (iClient->GetReceiveActive())
			{
				Activate();
			}
			else
			{
				EAP_TRACE_DEBUG(
					iTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: CEapServerProcessHandler::RunL(): cannot call User::RequestComplete() because no receive is active.\n")));
			}
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapServerProcessHandler::RunL(): No more messages to process.\n")));
	}

	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("=end======================================================================\n")));
}

//----------------------------------------------------------------------------

void CEapServerProcessHandler::DoCancel()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::DoCancel(): this=0x%08x\n"),
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::DoCancel()");

}

//----------------------------------------------------------------------------

TInt CEapServerProcessHandler::RunError(TInt aError)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapServerProcessHandler::RunError(): aError=%d, this=0x%08x\n"),
		aError,
		this));
	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapServerProcessHandler::RunError()");

	Cancel();

	return aError;
}

//----------------------------------------------------------------------------
// end
