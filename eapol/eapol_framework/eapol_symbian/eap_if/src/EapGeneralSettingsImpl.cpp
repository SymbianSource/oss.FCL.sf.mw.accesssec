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
* Description:  This is implementation of CEapGeneralSettings interface.
*
*/

/*
* %version: 52 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 740 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapGeneralSettingsImpl.h"
#include "EapConversion.h"
#include "eap_am_assert.h"
#include <EapTypeInfo.h>
#include "abs_eap_am_tools.h"
#include "eap_automatic_variable.h"
#include <utf.h>                           // for CnvUtfConverter
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_automatic_variable.h"
#include "eap_general_settings_message.h"
#include "eap_am_message_if_symbian.h"
#include "eap_process_tlv_message_data.h"
#include "eap_general_settings_client_message_if.h"

// LOCAL CONSTANTS

// The version number of this interface.
const TUint KInterfaceVersion = 1;


// ================= MEMBER FUNCTIONS =======================

CEapGeneralSettingsImpl::CEapGeneralSettingsImpl(
	const TIndexType aIndexType,	
	const TInt aIndex)
: m_am_tools(abs_eap_am_tools_c::new_abs_eap_am_tools_c())
, m_server(new_eap_general_settings_client_message_if_c(
		m_am_tools,
		this))
, iIndexType(aIndexType)
, iIndex(aIndex)
, iActiveEapMethods(0)
, iDisabledEapMethods(0)
, iUserCerts(0)
, iCACerts(0)
, iWaitState(eap_general_settings_wait_state_none)
, iCompletionStatus(eap_status_process_general_error)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::CEapGeneralSettingsImpl(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::CEapGeneralSettingsImpl()");

}

// ----------------------------------------------------------

void CEapGeneralSettingsImpl::ConstructL()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::ConstructL(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::ConstructL()");

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
		TInt aStatus = m_am_tools->convert_eapol_error_to_am_error(status);
			
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
		delete m_server;

		User::Leave(aStatus);
	}
}

// ----------------------------------------------------------

CEapGeneralSettingsImpl* CEapGeneralSettingsImpl::NewL(SIapInfo* aIapInfo)
{
	CEapGeneralSettingsImpl* self = new(ELeave) CEapGeneralSettingsImpl(aIapInfo->indexType, aIapInfo->index);

	CleanupStack::PushL(self);

	self->ConstructL();

	CleanupStack::Pop();

	return self;
}

// ----------------------------------------------------------

CEapGeneralSettingsImpl::~CEapGeneralSettingsImpl()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::~CEapGeneralSettingsImpl(): this=0x%08x.\n"),
		this));

	if (m_server != 0)
	{
		m_server->shutdown();
	}
	delete m_server;

	abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
}

// ----------------------------------------------------------

TUint CEapGeneralSettingsImpl::GetInterfaceVersion()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::GetInterfaceVersion(): this=0x%08x\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::GetInterfaceVersion()");

	return KInterfaceVersion;
}

//----------------------------------------------------------------

void CEapGeneralSettingsImpl::Activate()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::Activate(): iAsyncronousStatus=%u\n"),
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::Activate()");

	iAsyncronousStatus = KRequestPending;

}

//----------------------------------------------------------------

void CEapGeneralSettingsImpl::Complete()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::Complete(): iAsyncronousStatus=%u\n"),
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::Complete()");

	iAsyncronousStatus = KErrNone;

	// This is needed to continue the execution after Wait.Start(); 
	iWait.AsyncStop();
}

//----------------------------------------------------------------

void CEapGeneralSettingsImpl::WaitCompletion()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::WaitCompletion(): iAsyncronousStatus=%u\n"),
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::WaitCompletion()");

	while (iAsyncronousStatus == KRequestPending)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapGeneralSettingsImpl::WaitCompletion(): calls iWait.Start()\n")));

		iWait.Start();

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapGeneralSettingsImpl::WaitCompletion(): iWait.Start() returns, iAsyncronousStatus=%u\n"),
			iAsyncronousStatus.Int()));
	}
}

// ----------------------------------------------------------

void CEapGeneralSettingsImpl::SetCompletionStatusIfStillOk(const eap_status_e status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::SetCompletionStatusIfStillOk(): iCompletionStatus=%d=%s, status=%d=%s\n"),
		iCompletionStatus,
		eap_status_string_c::get_status_string(iCompletionStatus),
		status,
		eap_status_string_c::get_status_string(status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::SetCompletionStatusIfStillOk()");

	if (iCompletionStatus == eap_status_ok)
	{
		iCompletionStatus = status;
	}
}

// ----------------------------------------------------------

TInt CEapGeneralSettingsImpl::GetEapMethods(
	RArray<TEapExpandedType> & ActiveEapMethods,
	RArray<TEapExpandedType> & DisabledEapMethods)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::GetEapMethods(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::GetEapMethods()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(
		m_am_tools,
		internal_settings);

	if (internal_settings == 0)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	iActiveEapMethods = &ActiveEapMethods;
	iDisabledEapMethods = &DisabledEapMethods;

	eap_status_e status = m_server->get_eap_methods(internal_settings);

	iWaitState = eap_general_settings_wait_state_complete_get_eap_methods;
	Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus));
	}

	return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status));
}

// ----------------------------------------------------------

TInt CEapGeneralSettingsImpl::SetEapMethods(
	const RArray<TEapExpandedType> & ActiveEapMethods,
	const RArray<TEapExpandedType> & DisabledEapMethods)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::SetEapMethods(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::SetEapMethods()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(
		m_am_tools,
		internal_settings);

	if (internal_settings == 0)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;


	TInt error = CEapConversion::ConvertExpandedEAPTypesToInternalTypes(
		m_am_tools,
		&ActiveEapMethods,
		&(internal_settings->m_active_eap_methods));
	if (error != KErrNone)
	{
		return error;
	}


	error = CEapConversion::ConvertExpandedEAPTypesToInternalTypes(
		m_am_tools,
		&DisabledEapMethods,
		&(internal_settings->m_disabled_eap_methods));
	if (error != KErrNone)
	{
		return error;
	}

	internal_settings->m_SelectedEAPTypesPresent = true;

	eap_status_e status = m_server->set_eap_methods(internal_settings);

	iWaitState = eap_general_settings_wait_state_complete_set_eap_methods;
	Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus));
	}

	return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status));
}

// ----------------------------------------------------------

eap_status_e CEapGeneralSettingsImpl::complete_get_eap_methods(
	const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_get_eap_methods(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		internal_settings->m_completion_status,
		eap_status_string_c::get_status_string(internal_settings->m_completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::complete_get_eap_methods()");

	if (internal_settings == 0)
	{
		iCompletionStatus = eap_status_illegal_parameter;

		Complete();

		return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
	}

	iCompletionStatus = internal_settings->m_completion_status;

	if (iWaitState == eap_general_settings_wait_state_complete_get_eap_methods
		&& iCompletionStatus == eap_status_ok)
	{
		if (iActiveEapMethods != 0
			&& iDisabledEapMethods != 0
			&& internal_settings != 0)
		{
			TInt error(KErrNone);

			error = CEapConversion::ConvertInternalTypesToExpandedEAPTypes(
				m_am_tools,
				&(internal_settings->m_active_eap_methods),
				iActiveEapMethods);
			if (error != KErrNone)
			{
				SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error)));
			}
			else
			{
				error = CEapConversion::ConvertInternalTypesToExpandedEAPTypes(
					m_am_tools,
					&(internal_settings->m_disabled_eap_methods),
					iDisabledEapMethods);
				if (error != KErrNone)
				{
					SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error)));
				}
			}
		}
		else
		{
			SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter));
		}
	}
	else if (iCompletionStatus == eap_status_ok)
	{
		// ERROR, wrong state. Other function was completed successfully not the function that was waited.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
}

// ----------------------------------------------------------

eap_status_e CEapGeneralSettingsImpl::complete_set_eap_methods(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_set_eap_methods(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::complete_set_eap_methods()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_general_settings_wait_state_complete_set_eap_methods
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR, wrong state. Other function was completed successfully not the function that was waited.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------

TInt CEapGeneralSettingsImpl::GetCertificateLists(
	RPointerArray<EapCertificateEntry> & aUserCerts,
	RPointerArray<EapCertificateEntry> & aCACerts)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::GetCertificateLists(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::GetCertificateLists()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(
		m_am_tools,
		internal_settings);

	if (internal_settings == 0)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	iUserCerts = &aUserCerts;
	iCACerts = &aCACerts;

	eap_status_e status = m_server->get_certificate_lists(internal_settings);

	iWaitState = eap_general_settings_wait_state_complete_get_certificate_lists;
	Activate();
	WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus));
	}

	return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status));
}

// ----------------------------------------------------------

eap_status_e CEapGeneralSettingsImpl::complete_get_certificate_lists(
	const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_get_certificate_lists(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		internal_settings->m_completion_status,
		eap_status_string_c::get_status_string(internal_settings->m_completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::complete_get_certificate_lists()");

	if (internal_settings == 0)
	{
		// ERROR
		iCompletionStatus = eap_status_illegal_parameter;

		Complete();

		return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
	}

	iCompletionStatus = internal_settings->m_completion_status;

	if (iWaitState == eap_general_settings_wait_state_complete_get_certificate_lists
		&& iCompletionStatus == eap_status_ok)
	{
		if (iUserCerts != 0
			&& iCACerts != 0
			&& internal_settings != 0)
		{
			TInt error = CEapConversion::ConvertInternalTypeToCertificates(
				m_am_tools,
				eap_certificate_entry_c::eap_certificate_type_user,
				&(internal_settings->m_Certificates),
				iUserCerts);
			if (error != KErrNone)
			{
				// ERROR
				SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error)));
			}
			else
			{
				error = CEapConversion::ConvertInternalTypeToCertificates(
					m_am_tools,
					eap_certificate_entry_c::eap_certificate_type_CA,
					&(internal_settings->m_Certificates),
					iCACerts);
				if (error != KErrNone)
				{
					// ERROR
					SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error)));
				}
			}
		}
		else
		{
			// ERROR
			SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter));
		}
	}
	else if (iCompletionStatus == eap_status_ok)
	{
		// ERROR, wrong state. Other function was completed successfully not the function that was waited.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, iCompletionStatus);
}

// ----------------------------------------------------------

TInt CEapGeneralSettingsImpl::DeleteAllEapSettings()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::DeleteAllEapSettings(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::DeleteAllEapSettings()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(
		m_am_tools,
		internal_settings);

	if (internal_settings == 0)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;

	eap_status_e status = m_server->delete_all_eap_settings(internal_settings);

	iWaitState = eap_general_settings_wait_state_complete_delete_all_eap_settings;
	Activate();
	WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus));
	}

	return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status));
}

// ----------------------------------------------------------

TInt CEapGeneralSettingsImpl::CopyAllEapSettings(
	const TIndexType aDestinationIndexType,
	const TInt aDestinationIndex)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::CopyAllEapSettings(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::CopyAllEapSettings()");

	eap_method_settings_c * const internal_settings = new eap_method_settings_c(m_am_tools);

	eap_automatic_variable_c<eap_method_settings_c> automatic_internal_settings(
		m_am_tools,
		internal_settings);

	if (internal_settings == 0)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
	}

	internal_settings->m_IndexType = iIndexType;
	internal_settings->m_Index = iIndex;
	internal_settings->m_DestinationIndexType = aDestinationIndexType;
	internal_settings->m_DestinationIndex = aDestinationIndex;

	eap_status_e status = m_server->copy_all_eap_settings(internal_settings);

	iWaitState = eap_general_settings_wait_state_complete_copy_all_eap_settings;
	Activate();
	WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, iCompletionStatus));
	}

	return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, status));
}

// ----------------------------------------------------------

eap_status_e CEapGeneralSettingsImpl::complete_delete_all_eap_settings(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_delete_all_eap_settings(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::complete_delete_all_eap_settings()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_general_settings_wait_state_complete_delete_all_eap_settings
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR, wrong state. Other function was completed successfully not the function that was waited.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------

eap_status_e CEapGeneralSettingsImpl::complete_copy_all_eap_settings(
	const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_copy_all_eap_settings(): this=0x%08x, iWaitState=%d, status=%d=%s\n"),
		this,
		iWaitState,
		completion_status,
		eap_status_string_c::get_status_string(completion_status)));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapGeneralSettingsImpl::complete_copy_all_eap_settings()");

	iCompletionStatus = completion_status;

	if (iWaitState != eap_general_settings_wait_state_complete_copy_all_eap_settings
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR, wrong state. Other function was completed successfully not the function that was waited.
		SetCompletionStatusIfStillOk(EAP_STATUS_RETURN(m_am_tools, eap_status_wrong_eap_type_state));
	}

	Complete();

	return EAP_STATUS_RETURN(m_am_tools, completion_status);
}

// ----------------------------------------------------------
// ----------------------------------------------------------
// ----------------------------------------------------------

eap_am_message_if_c * eap_am_message_if_c::new_eap_am_message_if_c(
	abs_eap_am_tools_c * const tools)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_message_if_c::new_eap_am_server_general_settings_c()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: eap_am_message_if_c::new_eap_am_message_if_c()");

    eap_am_message_if_c *client_if = new eap_am_message_if_symbian_c(tools, EEapSettingsNew);

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

// ----------------------------------------------------------

eap_general_settings_message_c * new_eap_general_settings_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_general_settings_message_c * const partner)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("new_eap_general_settings_client_message_if_c()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: new_eap_general_settings_client_message_if_c()");

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
				(EAPL("ERROR: calls: new_eap_general_settings_client_message_if_c(): client_if->shutdown()\n")));

			(void) client_if->shutdown();
		}
		return 0;
	}

	eap_general_settings_client_message_if_c * new_session_core = new eap_general_settings_client_message_if_c(tools, client_if, partner);

	eap_automatic_variable_c<eap_general_settings_client_message_if_c> automatic_new_session_core(
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
				(EAPL("ERROR: calls: new_eap_general_settings_client_message_if_c(): new_session_core->shutdown()\n")));

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
