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
* Description:  interface to PAC-store.
*
*/

/*
* %version: 14 %
*/

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
#include "eap_am_pac_store_symbian.h"
#include "abs_eap_am_pac_store.h"
#include "eap_automatic_variable.h"
#include "EapTraceSymbian.h"
#include "EapConversion.h"
#include "eap_type_tls_peap_types.h"
#include "pac_store_db_parameters.h"
#include "pac_store_db_symbian.h"
#include <f32file.h>
#include "EapPluginDbDefaults.h"

/** @file */

// ----------------------------------------------------------------------
const TUint KMaxDBFieldNameLength = 255;

// ----------------------------------------------------------------------

eap_am_pac_store_symbian_c::eap_am_pac_store_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_am_pac_store_c * const partner)
	: m_am_tools(tools)
	, m_partner(partner)
	, m_is_valid(false)
	, m_shutdown_was_called(false)
	, iClientCreated(false)
	, iPacStoreSessionOpened(false)
	, iClient(NULL)
	, m_PAC_store_password(tools)

{

	if (m_am_tools == 0
		|| m_am_tools->get_is_valid() == false
		|| m_partner == 0)
	{
		return;
	}

	m_is_valid = true;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::eap_am_pac_store_symbian_c(): this=0x%08x.\n"),
		this));
		
	return;
}

// ----------------------------------------------------------------------

eap_am_pac_store_symbian_c::~eap_am_pac_store_symbian_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::~eap_am_pac_store_symbian_c(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::~eap_am_pac_store_symbian_c()");

	delete iClient;
	iClient = NULL;
	
	EAP_ASSERT(m_shutdown_was_called == true);
}

// ----------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_pac_store_symbian_c::get_is_valid()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::get_is_valid(): this=0x%08x. valid=%d\n"),
		this, m_is_valid));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::get_is_valid()");

	return m_is_valid;
}

// ----------------------------------------------------------------------

// This is documented in abs_eap_stack_interface_c::configure().
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::configure()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::configure(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::configure()");

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------------------

// This is documented in abs_eap_stack_interface_c::shutdown().
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::shutdown(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::shutdown()");

	m_shutdown_was_called = true;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::open_pac_store()
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::open_pac_store(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::open_pac_store()");

	TRAPD(err, iClient = CPacStoreDatabase::NewL());
	if (err || iClient == NULL)
			{
			m_partner->complete_open_pac_store(eap_status_process_general_error);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
			}
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_pac_store_symbian_c::open_pac_store Created PAC store")));	
		
	TRAP(err, iClient->OpenPacStoreL());
	if (err || iClient == NULL)
		{
		m_partner->complete_open_pac_store(eap_status_process_general_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
	EAP_TRACE_DEBUG_SYMBIAN(
			(_L("eap_am_pac_store_symbian_c::open_pac_store Opened PAC store")));	

	iClientCreated = ETrue;

	m_partner->complete_open_pac_store(eap_status_ok);
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::create_device_seed()
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::create_device_seed(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::create_device_seed()");

	if(iClientCreated == EFalse)
		{
		m_partner->complete_create_device_seed(eap_status_process_general_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

	eap_variable_data_c aDeviceSeed(m_am_tools);
	
	eap_status_e status = iClient->CreateDeviceSeed(&aDeviceSeed);

	m_partner->complete_create_device_seed(status);

	return EAP_STATUS_RETURN(m_am_tools, status);
	}


// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::is_master_key_present()
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::is_master_key_present(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::is_master_key_present()");

	TBool present = EFalse;
	if(iClientCreated == EFalse)
		{
		m_partner->complete_is_master_key_present(EFalse);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

	eap_status_e status(eap_status_ok);

	TRAPD(err, present = iClient->IsMasterKeyPresentL());
	if (err)
		{
		present = EFalse;
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	m_partner->complete_is_master_key_present(present);

	return EAP_STATUS_RETURN(m_am_tools, status);
	}


// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::is_master_key_and_password_matching(
		const eap_variable_data_c * const pac_store_password)
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::is_master_key_and_password_matching(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::is_master_key_and_password_matching()");

	TBool matching = EFalse;
	
	if(iClientCreated == EFalse)
		{
		m_partner->complete_is_master_key_and_password_matching(EFalse);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

	HBufC8* pacStorePW8(NULL);
	
	TRAPD(err, pacStorePW8 = HBufC8::NewL(pac_store_password->get_data_length()));
	if (err)
		{
		m_partner->complete_is_master_key_and_password_matching(EFalse);
		return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}
	
	TPtr8 pacStorePW8Ptr = 	pacStorePW8->Des();
	
	pacStorePW8Ptr.Copy(pac_store_password->get_data(), pac_store_password->get_data_length());
		
	eap_status_e status(eap_status_ok);

	TRAP(err, matching = iClient->IsMasterKeyAndPasswordMatchingL(pacStorePW8Ptr));
	if (err)
		{
		matching = EFalse;
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	delete pacStorePW8;	

	m_partner->complete_is_master_key_and_password_matching(matching);

	return EAP_STATUS_RETURN(m_am_tools, status);
	
	}

// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::create_and_save_master_key(
		const eap_variable_data_c * const pac_store_password)
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::create_and_save_master_key(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::create_and_save_master_key()");

	if(iClientCreated == EFalse)
		{
		m_partner->complete_create_and_save_master_key(eap_status_process_general_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

	HBufC8* pacStorePW8(NULL);
	
	eap_status_e status(eap_status_ok);

	TRAPD(err, pacStorePW8 = HBufC8::NewL(pac_store_password->get_data_length()));
	if (err)
		{
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		m_partner->complete_create_and_save_master_key(status);
		return EAP_STATUS_RETURN(m_am_tools, status);
		}
	
	TPtr8 pacStorePW8Ptr = 	pacStorePW8->Des();
	
	pacStorePW8Ptr.Copy(pac_store_password->get_data(), pac_store_password->get_data_length());

	TRAP(err, iClient->CreateAndSaveMasterKeyL(pacStorePW8Ptr));
	if (err)
		{
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	delete pacStorePW8;	

	m_partner->complete_create_and_save_master_key(status);

	return EAP_STATUS_RETURN(m_am_tools, status);
	}


// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::is_pacstore_password_present()
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::is_pacstore_password_present(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::is_pacstore_password_present()");

	TBool present = EFalse;
	if(iClientCreated == EFalse)
		{
		m_partner->complete_is_pacstore_password_present(EFalse);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

	eap_status_e status(eap_status_ok);

	TRAPD(err, present = iClient->IsPacPasswordPresentL());
	if (err)
		{
		present = EFalse;
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	m_partner->complete_is_pacstore_password_present(present);
	return EAP_STATUS_RETURN(m_am_tools, status);
	}


// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::compare_pac_store_password(
		eap_variable_data_c * const pac_store_password)
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::compare_pac_store_password(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::compare_pac_store_password()");

	TBool matching = EFalse;
	
	if(iClientCreated == EFalse)
		{
		m_partner->complete_compare_pac_store_password(EFalse);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

	HBufC8* pacStorePW8(NULL);
	
	TRAPD(err, pacStorePW8 = HBufC8::NewL(pac_store_password->get_data_length()));
	if (err)
		{
		m_partner->complete_compare_pac_store_password(EFalse);
		return EAP_STATUS_RETURN(m_am_tools, EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err)));
		}
	
	TPtr8 pacStorePW8Ptr = 	pacStorePW8->Des();
	
	pacStorePW8Ptr.Copy(pac_store_password->get_data(), pac_store_password->get_data_length());
		

	eap_status_e status(eap_status_ok);

	TRAP(err, matching = iClient->ComparePacStorePasswordL(pacStorePW8Ptr));
	if (err)
		{
		matching = EFalse;
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	delete pacStorePW8;

	m_partner->complete_compare_pac_store_password(matching);

	return EAP_STATUS_RETURN(m_am_tools, status);
	}

// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::set_pac_store_password(
		const eap_variable_data_c * pac_store_password)
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::set_pac_store_password(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::set_pac_store_password()");

	if(iClientCreated == EFalse)
		{
		m_partner->complete_set_pac_store_password(eap_status_process_general_error);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		
	TBuf<KMaxDBFieldNameLength> pacStoreDBColName;
	HBufC8* pacStoreDBColValBuf8(NULL);
	
	pacStoreDBColName.Copy(cf_str_EAP_FAST_PAC_store_password_literal);			

	eap_status_e status(eap_status_ok);

	TRAPD(err, pacStoreDBColValBuf8 = HBufC8::NewL(KMaxPasswordLengthInDB));
	if (err)
		{
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		m_partner->complete_set_pac_store_password(status);
		return EAP_STATUS_RETURN(m_am_tools, status);
		}

	TPtr8 pacStoreDBColValPtr8 = pacStoreDBColValBuf8->Des();
	pacStoreDBColValPtr8.Copy(pac_store_password->get_data(), pac_store_password->get_data_length());

	TRAP( err, iClient->SetPacStoreDataL(pacStoreDBColName, pacStoreDBColValPtr8));
	if (err)
		{
		status = EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
		}

	delete pacStoreDBColValBuf8;
	m_partner->complete_set_pac_store_password(status);
	return EAP_STATUS_RETURN(m_am_tools, status);
	}

// ----------------------------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_pac_store_symbian_c::destroy_pac_store()
	{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_pac_store_symbian_c::destroy_pac_store(): this=0x%08x.\n"),
		this));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_am_pac_store_symbian_c::destroy_pac_store()");

	if(iClientCreated == EFalse)
		{
		eap_status_e status(eap_status_process_general_error);

		m_partner->complete_destroy_pac_store(status);

		return EAP_STATUS_RETURN(m_am_tools, status);
		}

	iClient->DestroyPacStore();

	EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_pac_store_symbian_c::open_pac_store destroy_pac_store end")));

	m_partner->complete_destroy_pac_store(eap_status_ok);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

// End
