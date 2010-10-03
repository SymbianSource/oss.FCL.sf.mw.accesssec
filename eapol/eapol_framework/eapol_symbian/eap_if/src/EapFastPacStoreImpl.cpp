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
* %version: 30 %
*/

#include <e32base.h>
#include <ecom/implementationproxy.h>
#include "EapolUID.h"
#include "EapTraceSymbian.h"
#include "EapFastPacStoreImpl.h"
#include "eap_automatic_variable.h"

// ----------------------------------------------------------

const TImplementationProxy ImplementationTable[] = 
{
	{{0x2002BC93}, reinterpret_cast<TProxyNewLPtr> (CEapFastPacStoreImpl::NewL)}
};

// ----------------------------------------------------------

EXPORT_C const TImplementationProxy* ImplementationGroupProxy(TInt& aTableCount)
{
	aTableCount = sizeof(ImplementationTable) / sizeof(TImplementationProxy);

	return ImplementationTable;
}

// ----------------------------------------------------------

CEapFastPacStore* CEapFastPacStoreImpl::NewL()
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::NewL")));  

    CEapFastPacStoreImpl* self = new (ELeave) CEapFastPacStoreImpl();
		
	CleanupStack::PushL(self);
		
	self->ConstructL();

	CleanupStack::Pop(self);
	
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::NewL end")));  
	return self;
 	
}

// ----------------------------------------------------------

CEapFastPacStoreImpl::CEapFastPacStoreImpl():
   	iTools(abs_eap_am_tools_c::new_abs_eap_am_tools_c())
	  ,iPartner(eap_pac_store_message_base_c::new_eap_pac_store_client_message_if_c(
			iTools,
			this))
    ,iIsValid (EFalse)
   	,iWaitState(eap_fast_pac_store_impl_wait_state_none)
    ,iPacStorePassword (new eap_variable_data_c(iTools))
    ,iIsPresent(EFalse)
		,iIsMatching(EFalse)
	{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::CEapFastPacStoreImpl")));
		
		
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::CEapFastPacStoreImpl end")));  
	}
	
// ----------------------------------------------------------

void CEapFastPacStoreImpl::ConstructL()
	{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::ConstructL")));

	eap_status_e status = iPartner->configure();
	if (status != eap_status_ok)
		{
			TInt aError = iTools->convert_eapol_error_to_am_error(status);
			
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(iTools);
		delete iPartner;
		iPartner = NULL;
		User::Leave(aError);
		}
			
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::ConstructL end")));  
		
	}
	
// ----------------------------------------------------------

CEapFastPacStoreImpl::~CEapFastPacStoreImpl()
	{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::~CEapFastPacStoreImpl")));
 
     if ( iPacStorePassword != NULL )
        {
        delete iPacStorePassword;
        }

		if (iPartner != 0)
			{
			iPartner->shutdown();
			}
		delete iPartner;

    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::~CEapFastPacStoreImpl end")));  
		
		abs_eap_am_tools_c::delete_abs_eap_am_tools_c(iTools);
		iTools = NULL;
	}
	

// ----------------------------------------------------------

void CEapFastPacStoreImpl::Activate()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::Activate(): iAsyncronousStatus=%u\n"),
			iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapFastPacStoreImpl::Activate()");

	iAsyncronousStatus = KRequestPending;
}

//----------------------------------------------------------------

void CEapFastPacStoreImpl::Complete()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::Complete(): iAsyncronousStatus=%u\n"),
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapFastPacStoreImpl::Complete()");

	iAsyncronousStatus = KErrNone;

	// This is needed to continue the execution after Wait.Start(); 
	iWait.AsyncStop();
}

//----------------------------------------------------------------

void CEapFastPacStoreImpl::WaitCompletion()
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::WaitCompletion(): iAsyncronousStatus=%u\n"),
		iAsyncronousStatus.Int()));

	EAP_TRACE_RETURN_STRING(iTools, "returns: CEapFastPacStoreImpl::WaitCompletion()");

	while (iAsyncronousStatus == KRequestPending)
	{
		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapFastPacStoreImpl::WaitCompletion(): calls iWait.Start()\n")));

		iWait.Start();

		EAP_TRACE_DEBUG(
			iTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapFastPacStoreImpl::WaitCompletion(): iWait.Start() returns, iAsyncronousStatus=%u\n"),
			iAsyncronousStatus.Int()));
	}
}

// ----------------------------------------------------------

TBool CEapFastPacStoreImpl::IsMasterKeyPresentL()
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::IsMasterKeyPresentL")));  

	eap_status_e status = iPartner->is_master_key_present(
		iCompletionStatus);

	if (status != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, status)));
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_is_master_key_present;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus)));
	}

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::IsMasterKeyPresentL end")));  

	return iIsPresent;

}

// ----------------------------------------------------------

TBool CEapFastPacStoreImpl::IsMasterKeyAndPasswordMatchingL(
		const TDesC8 & aPassword8)
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::IsMasterKeyAndPasswordMatchingL")));  

	(void)iPacStorePassword->set_copy_of_buffer(aPassword8.Ptr(), aPassword8.Size());

	eap_status_e status = iPartner->is_master_key_and_password_matching(
		iPacStorePassword
		,iCompletionStatus);

	if (status != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, status)));
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_is_master_key_and_password_matching;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus)));
	}

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::IsMasterKeyAndPasswordMatchingL end")));  

	return iIsMatching;

}

// ----------------------------------------------------------

TInt CEapFastPacStoreImpl::CreateAndSaveMasterKeyL(
		const TDesC8 & aPassword8)
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::CreateAndSaveMasterKeyL")));  

	
	(void)iPacStorePassword->set_copy_of_buffer(aPassword8.Ptr(), aPassword8.Size());

	eap_status_e status = iPartner->create_and_save_master_key(
		iPacStorePassword
		,iCompletionStatus);

	if (status != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, status)));
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_create_and_save_master_key;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus)));
	}

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::CreateAndSaveMasterKeyL end")));  

  return iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus));

}

// ----------------------------------------------------------

TBool CEapFastPacStoreImpl::ComparePacStorePasswordL(
		TDes8 & aPassword8)
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::ComparePacStorePasswordL")));  

	(void)iPacStorePassword->set_copy_of_buffer(aPassword8.Ptr(), aPassword8.Size());

	eap_status_e status = iPartner->compare_pac_store_password(
		iPacStorePassword);
		
	if (status != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, status)));
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_compare_pac_store_password;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus)));
	}

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::ComparePacStorePasswordL end")));  
     
  return iIsPwMatching;

}

 TBool CEapFastPacStoreImpl::IsPacStorePasswordPresentL()
 	{
     EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::IsPacStorePasswordPresentL")));  

	eap_status_e status = iPartner->is_pacstore_password_present();

	if (status != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, status)));
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_is_pacstore_password_present;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus)));
	}

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::IsPacStorePasswordPresentL end")));  

	return iIsPwPresent;
		
 	}

// ----------------------------------------------------------

TInt CEapFastPacStoreImpl::SetPacStorePasswordL(
		const TDesC8 & aPassword8)
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::SetPacStorePasswordL")));  

	(void)iPacStorePassword->set_copy_of_buffer(aPassword8.Ptr(), aPassword8.Size());
	
	eap_status_e status = iPartner->set_pac_store_password(
		iPacStorePassword
		,iCompletionStatus);

	if (status != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, status)));
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_set_pac_store_password;
    Activate();
    WaitCompletion();

	if (iCompletionStatus != eap_status_ok)
	{
		User::Leave(iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus)));
	}

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::SetPacStorePasswordL end")));  

	return iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus));


}

// ----------------------------------------------------------

TInt CEapFastPacStoreImpl::DestroyPacStore()
{
    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::DestroyPacStore")));  

	eap_status_e status = iPartner->destroy_pac_store(
		iCompletionStatus);

	if (status != eap_status_ok)
	{
		return iTools->convert_eapol_error_to_am_error(status);
	}

	iWaitState = eap_fast_pac_store_impl_wait_state_complete_destroy_pac_store;
    Activate();
    WaitCompletion();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::DestroyPacStore end")));  

	return iTools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(iTools, iCompletionStatus));


}

// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_is_master_key_present(
		bool is_present
		,const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_is_master_key_present(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iIsPresent = is_present;
	iCompletionStatus = completion_status;

	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_is_master_key_present
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}
	
	iIsPresent = is_present;
	Complete();

    EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_is_master_key_present end")));  

	return iCompletionStatus;

}

// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_is_master_key_and_password_matching(
		bool is_matching
		,const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_is_master_key_and_password_matching(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iCompletionStatus = completion_status;

	iIsMatching = is_matching;
	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_is_master_key_and_password_matching
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}
	iIsMatching = is_matching;
	
	Complete();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_is_master_key_and_password_matching end")));  

	return iCompletionStatus;

}

// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_create_and_save_master_key(
		const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_create_and_save_master_key(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iCompletionStatus = completion_status;

	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_create_and_save_master_key
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}

	Complete();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_create_and_save_master_key end")));  

	return iCompletionStatus;

}

// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_compare_pac_store_password(
		bool is_matching)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_compare_pac_store_password(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iCompletionStatus = eap_status_ok;

	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_compare_pac_store_password)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}

	iIsPwMatching = is_matching;
	Complete();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_compare_pac_store_password end")));  

	return iCompletionStatus;

}

// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_is_pacstore_password_present(
		bool is_present)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_is_pacstore_password_present(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iCompletionStatus = eap_status_ok;

	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_is_pacstore_password_present)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}

	iIsPwPresent = is_present;
	Complete();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_is_pacstore_password_present end")));  

	return iCompletionStatus;

}
// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_set_pac_store_password(
		const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_set_pac_store_password(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iCompletionStatus = completion_status;

	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_set_pac_store_password
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}

	Complete();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_set_pac_store_password end")));  

	return iCompletionStatus;

}

// ----------------------------------------------------------

eap_status_e CEapFastPacStoreImpl::complete_destroy_pac_store(
		const eap_status_e completion_status)
{
	EAP_TRACE_DEBUG(
		iTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapFastPacStoreImpl::complete_destroy_pac_store(): this=0x%08x, iWaitState=%d\n"),
		this,
		iWaitState));

	iCompletionStatus = completion_status;

	if (iWaitState != eap_fast_pac_store_impl_wait_state_complete_destroy_pac_store
		&& iCompletionStatus == eap_status_ok)
	{
		// ERROR wrong state.
		iCompletionStatus = eap_status_wrong_eap_type_state;
	}

	Complete();

  EAP_TRACE_DEBUG_SYMBIAN(
     (_L("CEapFastPacStoreImpl::complete_destroy_pac_store end")));  

	return iCompletionStatus;

}

// ----------------------------------------------------------

eap_am_message_if_c * eap_am_message_if_c::new_eap_am_message_if_c(
	abs_eap_am_tools_c * const tools)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_message_if_c::new_eap_am_server_pac_store_message_c()\n")));

    eap_am_message_if_c *client_if = new eap_am_message_if_symbian_c(tools, EEapPacStoreNew);

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

EAP_FUNC_EXPORT eap_pac_store_message_base_c * eap_pac_store_message_base_c::new_eap_pac_store_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_pac_store_message_c * const partner)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_pac_store_message_base_c::new_eap_pac_store_client_message_if_c()\n")));

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
				(EAPL("ERROR: calls: eap_pac_store_message_base_c::new_eap_pac_store_client_message_if_c(): client_if->shutdown()\n")));

			(void) client_if->shutdown();
		}
		return 0;
	}

	eap_pac_store_client_message_if_c * new_session_core = new eap_pac_store_client_message_if_c(tools, client_if, partner);

	eap_automatic_variable_c<eap_pac_store_client_message_if_c> automatic_new_session_core(
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
				(EAPL("ERROR: calls: eap_pac_store_message_base_c::new_eap_pac_store_client_message_if_c(): new_session_core->shutdown()\n")));

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


