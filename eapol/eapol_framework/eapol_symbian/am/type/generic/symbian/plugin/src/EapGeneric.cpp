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
* %version: 62 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 739 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapGeneric.h"
#include "EapConversion.h"
#include "eap_base_type.h"
#include "eap_method_settings.h"
#include "eap_am_assert.h"
#include <EapTypeInfo.h>
#include "abs_eap_am_tools.h"
#include "eap_automatic_variable.h"
#include <utf.h>                           // for CnvUtfConverter
#include "abs_eap_plugin_message.h"
#include "eap_plugin_message_base.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_automatic_variable.h"
#include "eap_plugin_client_message_if.h"
#include "eap_am_message_if_symbian.h"
#include "EapTraceSymbian.h"

// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================


CEapGeneric::CEapGeneric(
	const TIndexType aIndexType,	
	const TInt aIndex,
	const TEapExpandedType aEapType)
: m_am_tools(abs_eap_am_tools_c::new_abs_eap_am_tools_c())
, m_server(eap_plugin_message_base_c::new_eap_plugin_client_message_if_c(
		m_am_tools,
		this))
, iIndexType(aIndexType)
, iIndex(aIndex)
, iEapType(aEapType)
, iTunnelingType(eap_type_none)
, iTunnelingTypePresent(false)
, iWaitState(eap_generic_wait_state_none)
, iCompletionStatus(eap_status_process_general_error)

, ipEAPSettings(0)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::CEapGeneric(): this=0x%08x, aIndexType=%d, aIndex=%d.\n"),
		this,
		aIndexType,
		aIndex));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::CEapGeneric()");
}

// ----------------------------------------------------------

void CEapGeneric::ConstructL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::ConstructL(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::ConstructL()");

	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false
		|| m_server == 0
		|| m_server->get_is_valid() == false)
	{
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
		delete m_server;

		User::Leave(KErrNoMemory);
	}

	eap_status_e status = m_server->configure();
	if (status != eap_status_ok)
	{
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
		delete m_server;

		User::Leave(KErrNoMemory);
	}
}

// ----------------------------------------------------------

CEapGeneric* CEapGeneric::NewL(SIapInfo *aIapInfo)
{
	CEapGeneric* self = new(ELeave) CEapGeneric(aIapInfo->indexType, aIapInfo->index, aIapInfo->aEapType);

	CleanupStack::PushL(self);

	self->ConstructL();

	CleanupStack::Pop();

	return self;
}

// ----------------------------------------------------------

CEapGeneric::~CEapGeneric()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::~CEapGeneric(): this=0x%08x.\n"),
		this));

	// Do not use m_am_tools, because it will be destroyed before return.
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapGeneric::~CEapGeneric()"));

	if (m_server != 0)
	{
		m_server->shutdown();
	}
	delete m_server;

	abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
}

// ----------------------------------------------------------

#ifdef USE_EAP_SIMPLE_CONFIG

eap_base_type_c* CEapGeneric::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const /* aPartner */,
											   const bool /* is_client_when_true */,
											   const eap_am_network_id_c * const /* receive_network_id */,
											   abs_eap_configuration_if_c * const /*configuration_if*/)
	
#else
	
eap_base_type_c* CEapGeneric::GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											abs_eap_base_type_c* const /* aPartner */,
											const bool /* is_client_when_true */,
											const eap_am_network_id_c * const /* receive_network_id */)
	
#endif // #ifdef USE_EAP_SIMPLE_CONFIG
{
	EAP_UNREFERENCED_PARAMETER(aTools);
	// This class does not have stack interface.
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: CEapGeneric::GetStackInterfaceL(): this=0x%08x\n"),
		this));

	EAP_ASSERT_ANYWAY_TOOLS(aTools);

	return 0;
}

//----------------------------------------------------------------

void CEapGeneric::Activate()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::Activate(): this=0x%08x, iAsyncronousStatus=%u\n"),
		this,
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::Activate()");

	iAsyncronousStatus = KRequestPending;
}

//----------------------------------------------------------------

void CEapGeneric::Complete()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::Complete(): this=0x%08x, iAsyncronousStatus=%u\n"),
		this,
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::Complete()");

	iAsyncronousStatus = KErrNone;

	// This is needed to continue the execution after Wait.Start(); 
	iWait.AsyncStop();
}

//----------------------------------------------------------------

void CEapGeneric::WaitCompletion()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::WaitCompletion(): this=0x%08x, iAsyncronousStatus=%u\n"),
		this,
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::WaitCompletion()");

	while (iAsyncronousStatus == KRequestPending)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapGeneric::WaitCompletion(): calls iWait.Start()\n")));

		iWait.Start();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapGeneric::WaitCompletion(): iWait.Start() continue, iAsyncronousStatus=%u\n"),
			iAsyncronousStatus.Int()));
	}
}

// ----------------------------------------------------------

void CEapGeneric::SetCompletionStatusIfStillOk(const eap_status_e status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::SetCompletionStatusIfStillOk(): this=0x%08x, iCompletionStatus=%u=%s, status=%d=%s\n"),
		this,
		iCompletionStatus,
		eap_status_string_c::get_status_string(iCompletionStatus),
		status,
		eap_status_string_c::get_status_string(status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::SetCompletionStatusIfStillOk()");

	if (iCompletionStatus == eap_status_ok)
	{
		iCompletionStatus = status;
	}
}

// ----------------------------------------------------------



// ----------------------------------------------------------

CEapTypeInfo* CEapGeneric::GetInfoL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::GetInfoL(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::GetInfoL()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);
	if (internal_settings == 0)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)));
	}

	iCompletionStatus = eap_status_process_general_error;

	eap_status_e status = m_server->get_type_info(internal_settings);

	delete internal_settings;

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_get_type_info;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}

	CEapTypeInfo* info = new(ELeave) CEapTypeInfo(
		iReleaseDate, 
		iEapTypeVersion,
		iManufacturer);

	return info;
}

// ----------------------------------------------------------

void CEapGeneric::DeleteConfigurationL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::DeleteConfigurationL(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::DeleteConfigurationL()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);
	if (internal_settings == 0)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)));
	}
	
	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	TInt error =  CEapConversion::ConvertExpandedEAPTypeToInternalType(
		&iEapType,
		&(internal_settings->m_EAPType));
	if (error != KErrNone)
	{
		delete internal_settings;

		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::Leave(error);
	}
	iCompletionStatus = eap_status_process_general_error;

	eap_status_e status = m_server->delete_configuration(internal_settings);

	delete internal_settings;

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_delete_configuration;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}
}

// ----------------------------------------------------------

TUint CEapGeneric::GetInterfaceVersion()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::GetInterfaceVersion(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::GetInterfaceVersion()");

	return KInterfaceVersion;
}

// ----------------------------------------------------------

void CEapGeneric::SetTunnelingType(const TEapExpandedType aTunnelingType)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::SetTunnelingType(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::SetTunnelingType()");

    EAP_TRACE_DATA_DEBUG_SYMBIAN(
        (EAPL("CEapGeneric::SetTunnelingType - tunneling type"),
        aTunnelingType.GetValue().Ptr(), aTunnelingType.GetValue().Length()));

    iTunnelingTypePresent = true;

	eap_type_value_e aInternalType;

	TInt error = CEapConversion::ConvertExpandedEAPTypeToInternalType(
	        &aTunnelingType,
	        &aInternalType);
	if (error != KErrNone)
	{
		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
	}

	iTunnelingType = aInternalType;
	
}


// ----------------------------------------------------------

void CEapGeneric::SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex )
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::SetIndexL(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::SetIndexL()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);
	if (internal_settings == 0)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)));
	}
	
	internal_settings->m_IndexType = aIndexType;
	internal_settings->m_Index = aIndex;

	TInt error =  CEapConversion::ConvertExpandedEAPTypeToInternalType(
		&iEapType,
		&(internal_settings->m_EAPType));
	if (error != KErrNone)
	{
		delete internal_settings;

		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::Leave(error);
	}

	iCompletionStatus = eap_status_process_general_error;

	eap_status_e status = m_server->delete_configuration(internal_settings);

	if (status != eap_status_ok)
	{
		delete internal_settings;

		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_delete_configuration;
	Activate();
	WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		delete internal_settings;

		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	error =  CEapConversion::ConvertExpandedEAPTypeToInternalType(
		&iEapType,
		&(internal_settings->m_EAPType));
	if (error != KErrNone)
	{
		delete internal_settings;

		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::Leave(error);
	}

	internal_settings->m_TunnelingTypePresent = iTunnelingTypePresent;
	internal_settings->m_TunnelingType = iTunnelingType;

	internal_settings->m_DestinationIndexAndTypePresent = true;
	internal_settings->m_DestinationIndexType = aIndexType;
	internal_settings->m_DestinationIndex = aIndex;

	iCompletionStatus = eap_status_process_general_error;

	status = m_server->set_index(internal_settings);

	delete internal_settings;

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_set_index;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}

}

// ----------------------------------------------------------

void CEapGeneric::SetConfigurationL(const EAPSettings& aSettings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::SetConfigurationL(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::SetConfigurationL()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);
	if (internal_settings == 0)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)));
	}

	eap_status_e status(eap_status_process_general_error);

	TInt error(KErrNone);

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	internal_settings->m_TunnelingTypePresent = iTunnelingTypePresent;
	internal_settings->m_TunnelingType = iTunnelingType;

	error = CEapConversion::ConvertEAPSettingsToInternalType(
		m_am_tools,
		&aSettings,
		internal_settings);
	if(error == KErrNone)
	{
		TInt error =  CEapConversion::ConvertExpandedEAPTypeToInternalType(
			&iEapType,
			&(internal_settings->m_EAPType));
		if (error != KErrNone)
		{
			delete internal_settings;

			(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
			User::Leave(error);
		}

		iCompletionStatus = eap_status_process_general_error;

		status = m_server->set_configuration(internal_settings);
	}
	else
	{
		status = m_am_tools->convert_am_error_to_eapol_error(error);
	}

	delete internal_settings;

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_set_configuration;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}
}

// ----------------------------------------------------------

void CEapGeneric::GetConfigurationL(EAPSettings& aSettings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::GetConfigurationL(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::GetConfigurationL()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);
	if (internal_settings == 0)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	TInt error =  CEapConversion::ConvertExpandedEAPTypeToInternalType(
		&iEapType,
		&(internal_settings->m_EAPType));
	if (error != KErrNone)
	{
		delete internal_settings;

		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::Leave(error);
	}

	internal_settings->m_TunnelingTypePresent = iTunnelingTypePresent;
	internal_settings->m_TunnelingType = iTunnelingType;

	ipEAPSettings = &aSettings;

	iCompletionStatus = eap_status_process_general_error;

	eap_status_e status = m_server->get_configuration(internal_settings);

	delete internal_settings;

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_get_configuration;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}
}

// ----------------------------------------------------------

void CEapGeneric::CopySettingsL(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::CopySettingsL(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::CopySettingsL()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);
	if (internal_settings == 0)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error)));
	}

	internal_settings->m_IndexType = aDestinationIndexType;
	internal_settings->m_Index = aDestinationIndex;

	iCompletionStatus = eap_status_process_general_error;

	eap_status_e status = m_server->delete_configuration(internal_settings);

	if (status != eap_status_ok)
	{
		delete internal_settings;

		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_delete_configuration;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		delete internal_settings;

		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	TInt error =  CEapConversion::ConvertExpandedEAPTypeToInternalType(
		&iEapType,
		&(internal_settings->m_EAPType));
	if (error != KErrNone)
	{
		delete internal_settings;

		(void)EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
		User::Leave(error);
	}

	internal_settings->m_TunnelingTypePresent = iTunnelingTypePresent;
	internal_settings->m_TunnelingType = iTunnelingType;

	internal_settings->m_DestinationIndexAndTypePresent = true;
	internal_settings->m_DestinationIndexType = aDestinationIndexType;
	internal_settings->m_DestinationIndex = aDestinationIndex;

	iCompletionStatus = eap_status_process_general_error;

	status = m_server->copy_configuration(internal_settings);

	delete internal_settings;

	if (status != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status)));
	}

	iWaitState = eap_generic_wait_state_complete_copy_configuration;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus)));
	}
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_get_configuration(
	const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_get_configuration(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		internal_settings->m_completion_status,
		eap_status_string_c::get_status_string(internal_settings->m_completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_get_configuration()");

	if (internal_settings == 0)
	{
		iCompletionStatus = eap_status_illegal_parameter;

		Complete();

		return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
	}

	iCompletionStatus = internal_settings->m_completion_status;

	if (iWaitState == eap_generic_wait_state_complete_get_configuration
		&& iCompletionStatus == eap_status_ok)
	{
		if (ipEAPSettings != 0
			&& internal_settings != 0)
		{
			TInt error(KErrNone);

			error = CEapConversion::ConvertInternalTypeToEAPSettings(
				m_am_tools,
				internal_settings,
				ipEAPSettings);
			if(error != KErrNone)
			{
				SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error)));
			}
		}
		else
		{
			SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter));
		}
	}
	else if (iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_set_configuration(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_set_configuration(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_set_configuration()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_generic_wait_state_complete_set_configuration
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_delete_configuration(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_delete_configuration(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_delete_configuration()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_generic_wait_state_complete_delete_configuration
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_copy_configuration(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_copy_configuration(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_copy_configuration()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_generic_wait_state_complete_copy_configuration
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_set_index(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_set_index(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_set_index()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_generic_wait_state_complete_set_index
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_get_type_info(
	const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_get_type_info(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		internal_settings->m_completion_status,
		eap_status_string_c::get_status_string(internal_settings->m_completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_get_type_info()");

	if (internal_settings == 0)
	{
		iCompletionStatus = eap_status_illegal_parameter;

		Complete();

		return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
	}

	iCompletionStatus = internal_settings->m_completion_status;

	if (iWaitState == eap_generic_wait_state_complete_get_type_info
		&& iCompletionStatus == eap_status_ok)
	{
		if (internal_settings != 0
			&& internal_settings->m_MethodInfoPresent == true)
		{
			TInt error(KErrNone);

			error = CEapConversion::ConvertFromInternalToBuf16(
				m_am_tools,
				&(internal_settings->m_KReleaseDate),
				&iReleaseDate);

			if(error == KErrNone)
			{
				error = CEapConversion::ConvertFromInternalToBuf16(
					m_am_tools,
					&(internal_settings->m_KEapTypeVersion),
					&iEapTypeVersion);
			}

			if(error == KErrNone)
			{
				error = CEapConversion::ConvertFromInternalToBuf16(
					m_am_tools,
					&(internal_settings->m_KManufacturer),
					&iManufacturer);
			}

			if(error != KErrNone)
			{
				SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error)));
			}
		}
		else
		{
			SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter));
		}
	}
	else if (iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
}

// ----------------------------------------------------------

eap_status_e CEapGeneric::complete_invoke_ui(
	const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneric::complete_invoke_ui(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		internal_settings->m_completion_status,
		eap_status_string_c::get_status_string(internal_settings->m_completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneric::complete_invoke_ui()");

	if (internal_settings == 0)
	{
		iCompletionStatus = eap_status_illegal_parameter;

		Complete();

		return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
	}

	iCompletionStatus = internal_settings->m_completion_status;

	if (iWaitState == eap_generic_wait_state_complete_invoke_ui
		&& iCompletionStatus == eap_status_ok)
	{
		if (internal_settings != 0
			&& internal_settings->m_ButtonIdPresent == true)
		{

		}
		else
		{
			SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter));
		}
	}
	else if (iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
}


//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

eap_am_message_if_c * eap_am_message_if_c::new_eap_am_message_if_c(
	abs_eap_am_tools_c * const tools)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_message_if_c::new_eap_am_server_general_settings_c()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: eap_am_message_if_c::new_eap_am_message_if_c()");

    eap_am_message_if_c *client_if = new eap_am_message_if_symbian_c(tools, EEapPluginNew);

	eap_automatic_variable_c<eap_am_message_if_c> automatic_client_if(
		tools,
		client_if);

	if (client_if == 0
		|| client_if->get_is_valid() == false)
	{
		// ERROR.
		if (client_if != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: calls: eap_am_message_if_c::new_eap_am_server_general_settings_c(): client_if->shutdown()\n")));

			client_if->shutdown();
		}
		return 0;
	}

	automatic_client_if.do_not_free_variable();

	return client_if;

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_plugin_message_base_c * eap_plugin_message_base_c::new_eap_plugin_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_plugin_message_c * const partner)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_plugin_message_base_c::new_eap_plugin_client_message_if_c()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: eap_plugin_message_base_c::new_eap_plugin_client_message_if_c()");

	eap_am_message_if_c *client_if = eap_am_message_if_c::new_eap_am_message_if_c(
		tools);

	eap_automatic_variable_c<eap_am_message_if_c> automatic_client_if(
		tools,
		client_if);

	if (client_if == 0
		|| client_if->get_is_valid() == false)
	{
		// ERROR.
		if (client_if != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: calls: eap_plugin_message_base_c::new_eap_plugin_client_message_if_c(): client_if->shutdown()\n")));

			(void) client_if->shutdown();
		}
		return 0;
	}

	eap_plugin_client_message_if_c * new_session_core = new eap_plugin_client_message_if_c(tools, client_if, partner);

	eap_automatic_variable_c<eap_plugin_client_message_if_c> automatic_new_session_core(
		tools,
		new_session_core);

	if (new_session_core == 0
		|| new_session_core->get_is_valid() == false)
	{
		// ERROR.
		if (new_session_core != 0)
		{
			EAP_TRACE_DEBUG(
				tools,
				TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT, 
				(EAPL("ERROR: calls: eap_plugin_message_base_c::new_eap_plugin_client_message_if_c(): new_session_core->shutdown()\n")));

			new_session_core->shutdown();
		}
		return 0;
	}

	client_if->set_partner(new_session_core);

	automatic_client_if.do_not_free_variable();
	automatic_new_session_core.do_not_free_variable();

	return new_session_core;
}

// ----------------------------------------------------------
// End of file
