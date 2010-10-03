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
* %version: 38 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 264 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include <coemain.h>
#include <bautils.h>
#include <barsc.h>
#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_type_mschapv2_symbian.h"
#include "EapMsChapV2DbParameterNames.h"
#include "EapMsChapV2DbDefaults.h"
#include "EapMsChapV2DbUtils.h"
#include "EapMsChapV2NotifierUids.h"
#include "eap_state_notification.h"

#include "EapTraceSymbian.h"

const TUint KMaxSqlQueryLength = 256;
const TUint KMaxDBFieldNameLength = 255;
const char EAP_MSCHAPV2_CREDENTIAL_HANDLE_KEY[] = "eap_type_mschapv2_c credential_store";
const TInt 	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMicroSecsInASecond = 1000000; // 1000000 micro seconds is 1 second.

// ================= MEMBER FUNCTIONS =======================

EAP_FUNC_EXPORT eap_am_type_mschapv2_symbian_c::~eap_am_type_mschapv2_symbian_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_mschapv2_symbian_c::~eap_am_type_mschapv2_symbian_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);	

	m_database.Close();
	m_session.Close();

	delete m_username_password_io_ptr;
	delete m_username_password_io_pckg_ptr;

	if (iEapAuthNotifier != 0)
		{
		delete iEapAuthNotifier;
		iEapAuthNotifier = 0;
		}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_mschapv2_symbian_c::shutdown(): this = 0x%08x\n"),
		this));
		



	m_shutdown_was_called = true;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_mschapv2_symbian_c::shutdown(): this = 0x%08x returns\n"),
		this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

eap_am_type_mschapv2_symbian_c::eap_am_type_mschapv2_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
: CActive(CActive::EPriorityStandard)
, eap_am_type_mschapv2_c(tools /*, partner */)
, m_am_tools(static_cast<eap_am_tools_symbian_c *> (tools))
, m_partner(partner)
, m_state(EHandlingUsernamePasswordQuery)
, m_username_utf8(0)
, m_password_utf8(0)
, m_old_password_utf8(0)
, m_password_prompt_enabled(0)
, m_is_identity_query(false)
, m_username_password_io_ptr(0)
, m_username_password_io_pckg_ptr(0)
, m_receive_network_id(tools)
, m_index_type(aIndexType)
, m_index(aIndex)
, m_tunneling_type(aTunnelingType)
, m_is_client(aIsClient)
, m_is_valid(false)
, m_shutdown_was_called(false)

, m_max_session_time(0)
	, iEapAuthNotifier(0)	


{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	if (receive_network_id != 0
		&& receive_network_id->get_is_valid_data() == true)
	{
		eap_status_e status = m_receive_network_id.set_copy_of_network_id(
			receive_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void)EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return;
		}
	}

	set_is_valid();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

eap_am_type_mschapv2_symbian_c * eap_am_type_mschapv2_symbian_c::NewL(
	abs_eap_am_tools_c * const aTools,
	abs_eap_base_type_c * const aPartner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
{
	eap_am_type_mschapv2_symbian_c * self = new eap_am_type_mschapv2_symbian_c(
		aTools,
		aPartner,
		aIndexType,
		aIndex,
		aTunnelingType,
		aIsClient,
		receive_network_id);

	if (self == 0
		|| self->get_is_valid() != true)
	{
		if (self != 0)
		{
			self->shutdown();
		}

		delete self;

		User::Leave(KErrGeneral);
	}

	TRAPD(error, self->ConstructL());

	if (error != KErrNone)
	{
		self->shutdown();
		delete self;

		User::Leave(error);
	}

	return self;
}

void eap_am_type_mschapv2_symbian_c::ConstructL()
{
	// NOTE: Do not use m_partner here without null check

	TInt error = m_session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_type_mschapv2_symbian_c::ConstructL(): - m_session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// Open/create the database
	EapMsChapV2DbUtils::OpenDatabaseL(m_database, m_session, m_index_type, m_index, m_tunneling_type);

	m_username_password_io_ptr = new(ELeave) CEapAuthNotifier::TEapDialogInfo;
	m_username_password_io_pckg_ptr = new(ELeave) TPckg<CEapAuthNotifier::TEapDialogInfo> (*m_username_password_io_ptr);

	CActiveScheduler::Add(this);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_mschapv2_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_type_mschapv2_symbian_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

void eap_am_type_mschapv2_symbian_c::send_error_notification(const eap_status_e error)
{
	eap_general_state_variable_e general_state_variable(eap_general_state_authentication_error);
	
	if (error == eap_status_user_cancel_authentication)
		{
		general_state_variable = eap_general_state_authentication_cancelled;
		}
	// Here we swap the addresses.
	eap_am_network_id_c send_network_id(m_am_tools,
		m_receive_network_id.get_destination_id(),
		m_receive_network_id.get_source_id(),
		m_receive_network_id.get_type());

	// Notifies the lower level of an authentication error.
	eap_state_notification_c notification(
		m_am_tools,
		&send_network_id,
		m_is_client,
		eap_state_notification_eap,
		eap_protocol_layer_general,
		eap_type_mschapv2,
		eap_state_none,
		general_state_variable,
		0,
		false);

	notification.set_authentication_error(error);

	m_partner->state_notification(&notification);
}

//--------------------------------------------------
TBool eap_am_type_mschapv2_symbian_c::IsMasterKeyAndPasswordMatchingL(
	      const TDesC16 & /*aPassword8*/)
{
	return EFalse;
}

//--------------------------------------------------
EAP_FUNC_EXPORT void eap_am_type_mschapv2_symbian_c::DlgComplete( TInt aStatus )
	{
	if (aStatus == KErrCancel)
		{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_am_type_mschapv2_symbian_c::RunL - User seems to have cancelled the prompt. Stop Immediately.\n")));
		
		// User cancelled the password prompt. Stop everything.
		// Appropriate error notification is sent from finish_unsuccessful_authentication.
		get_am_partner()->finish_unsuccessful_authentication(true);
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;
		}

	if (aStatus != KErrNone)
		{
		// Something is very wrong...
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP - MS-Chap-V2 notifier or dialog, aStatus=%d\n"), aStatus));

		send_error_notification(eap_status_authentication_failure);

		get_am_partner()->finish_unsuccessful_authentication(false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;
		}

	eap_status_e status(eap_status_ok);

	switch (m_state)
		{
		case EHandlingUsernamePasswordQuery:
			{
			if (m_username_password_io_ptr->iPasswordPromptEnabled)
				{
				*m_password_prompt_enabled = true;
				}
			else
				{
				*m_password_prompt_enabled = false;
				}

				{
				eap_variable_data_c tmp_username_unicode(
					m_am_tools);

				status = tmp_username_unicode.set_buffer(
					m_username_password_io_ptr->iUsername.Ptr(),
					m_username_password_io_ptr->iUsername.Size(),
					false,
					false);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				eap_variable_data_c tmp_username_utf8(m_am_tools);
				status = m_am_tools->convert_unicode_to_utf8(tmp_username_utf8, tmp_username_unicode);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				status = m_username_utf8->set_copy_of_buffer(&tmp_username_utf8);
				if (status != eap_status_ok)
					{
					get_am_partner()->finish_unsuccessful_authentication(false);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}
				}

				{
				eap_variable_data_c tmp_password_unicode(
					m_am_tools);

				status = tmp_password_unicode.set_buffer(
					m_username_password_io_ptr->iPassword.Ptr(),
					m_username_password_io_ptr->iPassword.Size(),
					false,
					false);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				eap_variable_data_c tmp_password_utf8(m_am_tools);
				status = m_am_tools->convert_unicode_to_utf8(tmp_password_utf8, tmp_password_unicode);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				status = m_password_utf8->set_copy_of_buffer(&tmp_password_utf8);
				if (status != eap_status_ok)
					{
					get_am_partner()->finish_unsuccessful_authentication(false);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}
				}

			// Store username and/or password if "Prompt for username" is enabled
			status = update_username_password();
			if (status != eap_status_ok)
				{
				get_am_partner()->finish_unsuccessful_authentication(false);
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				return;
				}

			if (m_is_identity_query)
				{
				status = get_am_partner()->complete_eap_identity_query();
				}
			else
				{
				status = get_am_partner()->complete_failure_retry_response();
				}
			}
		break;

	case EHandlingChangePasswordQuery:
		{
				{
				eap_variable_data_c tmp_password_unicode(
					m_am_tools);

				status = tmp_password_unicode.set_buffer(
					m_username_password_io_ptr->iPassword.Ptr(),
					m_username_password_io_ptr->iPassword.Size(),
					false,
					false);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				eap_variable_data_c tmp_password_utf8(m_am_tools);
				status = m_am_tools->convert_unicode_to_utf8(tmp_password_utf8, tmp_password_unicode);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				eap_status_e status = m_password_utf8->set_copy_of_buffer(&tmp_password_utf8);
				if (status != eap_status_ok)
					{
					get_am_partner()->finish_unsuccessful_authentication(false);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
					return;
					}
				}

				{
				eap_variable_data_c tmp_old_password_unicode(
					m_am_tools);

				status = tmp_old_password_unicode.set_buffer(
					m_username_password_io_ptr->iOldPassword.Ptr(),
					m_username_password_io_ptr->iOldPassword.Size(),
					false,
					false);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				eap_variable_data_c tmp_old_password_utf8(m_am_tools);
				status = m_am_tools->convert_unicode_to_utf8(tmp_old_password_utf8, tmp_old_password_unicode);
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					(void) EAP_STATUS_RETURN(m_am_tools, status);
					return;
					}

				status = m_old_password_utf8->set_copy_of_buffer(&tmp_old_password_utf8);
				if (status != eap_status_ok)
					{
					get_am_partner()->finish_unsuccessful_authentication(false);
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
					return;
					}
				}

			status = get_am_partner()->complete_change_password_query();
			}
		break;

	default:
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP - MS-Chap-V2 illegal state in RunL.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;		

		}
	}

//--------------------------------------------------

void eap_am_type_mschapv2_symbian_c::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::RunL - start")
		 EAPL("m_state, iStatus.Int()=%d\n"),
		 m_state, iStatus.Int()));


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

void eap_am_type_mschapv2_symbian_c::DoCancel()
{
	if (iEapAuthNotifier != 0)
		{
		iEapAuthNotifier->Cancel();
		}


	}

//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::type_configure_read(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT(data != 0);
	// Trap must be set here because the OS independent portion of EAP MSCHAPV2
	// that calls this function does not know anything about Symbian.	
	eap_status_e status(eap_status_ok);
	TRAPD(err, type_configure_readL(
		field->get_field(),
		field->get_field_length(),
		data));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);

		// Read is routed to partner object.
		status = m_partner->read_configure(
				field,
				data);
	}

	m_am_tools->trace_configuration(
		status,
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_mschapv2_symbian_c::type_configure_readL(
	eap_config_string field,
	const u32_t field_length,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(field_length);

	// Create a buffer for the ascii strings - initialised with the argument
	HBufC16* unicodeBuf = HBufC16::NewLC(KMaxDBFieldNameLength);
	TPtr16 unicodeString = unicodeBuf->Des();

	TPtrC8 fieldPtr(reinterpret_cast<const TUint8 *> (field), field_length);

	unicodeString.Copy(fieldPtr);
			
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQueryRow,
		&unicodeString,
		&KMsChapV2TableName,
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
	
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	
	if (view.FirstL())
	{
		eap_status_e status = eap_status_ok;
		view.GetL();		

		switch (view.ColType(KDefaultColumnInView_One))
		{
		case EDbColText:
			{
				if (view.ColLength(KDefaultColumnInView_One) > 0)
				{
					TPtrC16 value = view.ColDes16(KDefaultColumnInView_One);

					eap_variable_data_c string_unicode(m_am_tools);

					status = string_unicode.set_copy_of_buffer(value.Ptr(), value.Size());
					if (status != eap_status_ok)
					{
						User::Leave(
							m_am_tools->convert_eapol_error_to_am_error(
								EAP_STATUS_RETURN(m_am_tools, status)));
					}

					status = m_am_tools->convert_unicode_to_utf8(
						*data,
						string_unicode);
					if (status != eap_status_ok)
					{
						User::Leave(
							m_am_tools->convert_eapol_error_to_am_error(
								EAP_STATUS_RETURN(m_am_tools, status)));
					}
				} 
				else 
				{
					data->reset();
					status = data->set_copy_of_buffer("", 0);
					if (status != eap_status_ok)
					{
						User::Leave(
							m_am_tools->convert_eapol_error_to_am_error(
								EAP_STATUS_RETURN(m_am_tools, status)));
					}
				}
			}
			break;

		case EDbColUint32:
			{
				TUint value = view.ColUint32(KDefaultColumnInView_One);
				status = data->set_copy_of_buffer(reinterpret_cast<unsigned char *> (&value), sizeof(value));
				if (status != eap_status_ok)
				{
					User::Leave(
						m_am_tools->convert_eapol_error_to_am_error(
							EAP_STATUS_RETURN(m_am_tools, status)));
				}
			}
			break;

		default:
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("type_configure_readL: Unexpected column type.\n")));
			User::Leave(KErrGeneral);
			break;
		}
	} 
	else 
	{
		// Could not find parameter
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("type_configure_readL: Could not find configuration parameter.\n")));
		User::Leave(KErrArgument);
	}		
	
	CleanupStack::PopAndDestroy(3); // Close view, 2 x buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::type_configure_write(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			data);
	return status;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::update_username_password()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_ok);
	TRAPD(err, type_configure_updateL());
	if (err != KErrNone) 
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
	} 
	
	// User entered username/password and pressed OK.
	// Treat this as a full authentication and update the Last Auth Time.
	status = store_authentication_time();
	if (status != eap_status_ok)
	{
		// Storing failed. Don't care.
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_mschapv2_symbian_c:Storing Last Full Authentication time failed, status=%d, but continuing\n"), 
			status));

		status = eap_status_ok;
	}
				
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_mschapv2_symbian_c::type_configure_updateL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Now do the database update
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLUpdate, "SELECT %S,%S,%S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLUpdate,
		&cf_str_EAP_MSCHAPV2_username_literal,
		&cf_str_EAP_MSCHAPV2_password_prompt_literal,
		&cf_str_EAP_MSCHAPV2_password_literal,
		&KMsChapV2TableName,
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
	
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), RDbView::EUpdatable));
	CleanupClosePushL(view);

	view.FirstL();
	view.GetL();
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);	

	EAP_ASSERT(m_username_utf8 != 0);

	eap_status_e status(eap_status_ok);

	{
		eap_variable_data_c tmp_username_unicode(m_am_tools);

		status = m_am_tools->convert_utf8_to_unicode(tmp_username_unicode, *m_username_utf8);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		TPtr8 username(
			static_cast<TUint8*> (
				tmp_username_unicode.get_data()),
			tmp_username_unicode.get_data_length(),
			tmp_username_unicode.get_data_length());

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("type_configure_updateL - username"),
			 username.Ptr(),
			 username.Size()));
			
		// Validate length.
		if(username.Length() > KMaxUsernameLengthInDB)
		{
			// Username too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_type_mschapv2_symbian_c::type_configure_updateL: Too long Username. Length=%d \n"),
			username.Length()));
			
			User::Leave(KErrArgument);
		}
		
		// Length is ok. Set the value in DB.
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_username_literal), username);
	}

	if (*m_password_prompt_enabled)
	{
		// Username and password prompt flag is stored, password is cleared
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EEapDbTrue);
		view.SetColNullL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal));
	}
	else
	{
		eap_variable_data_c tmp_password_unicode(m_am_tools);

		status = m_am_tools->convert_utf8_to_unicode(tmp_password_unicode, *m_password_utf8);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return;
		}

		TPtr8 password(
			static_cast<TUint8*> (
				tmp_password_unicode.get_data()),
			tmp_password_unicode.get_data_length(),
			tmp_password_unicode.get_data_length());

		// Validate length.
		if(password.Length() > KMaxPasswordLengthInDB)
		{
			// Password too long. Can not be stored in DB.
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_type_mschapv2_symbian_c::type_configure_updateL: Too long Password. Length=%d \n"),
			password.Length()));
			
			User::Leave(KErrArgument);
		}

		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal), EEapDbFalse);

		// Length is ok. Set the value in DB.			
		view.SetColL(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_literal), password);
	}

	view.PutL();

	CleanupStack::PopAndDestroy( colSet ); // Delete colSet.			

	CleanupStack::PopAndDestroy(2); // view, buf
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	{
		// Read Maximum Session Validity Time from the config file
		eap_variable_data_c sessionTimeFromFile(m_am_tools);
		
		eap_status_e status = type_configure_read(
			cf_str_EAP_MSCHAPv2_max_session_validity_time.get_field(),
			&sessionTimeFromFile);
		
		if (status == eap_status_ok
			&& sessionTimeFromFile.get_is_valid_data() == true
			&& sessionTimeFromFile.get_data_length() == sizeof(u32_t))
		{
			u32_t *session = reinterpret_cast<u32_t *>(sessionTimeFromFile.get_data());
			if (session != 0)
			{
				// Update the max session time (in micro seconds).
				// configuration file saves the time in seconds. We have to convert it to micro seconds.
				m_max_session_time = static_cast<TInt64>(*session) * static_cast<TInt64>(KMicroSecsInASecond);
			}
		}		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::reset()
{
	return eap_status_ok;
}

//--------------------------------------------------

eap_status_e eap_am_type_mschapv2_symbian_c::show_username_password_dialog(
		eap_variable_data_c & username_utf8,
		eap_variable_data_c & password_utf8,
		bool & password_prompt_enabled,
		bool is_identity_query)    
{
	eap_status_e status = eap_status_ok;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_mschapv2_symbian_c::show_username_password_dialog - start, password_prompt_enabled=%d,is_identity_query=%d\n"),
		password_prompt_enabled, is_identity_query));

	m_username_utf8 = &username_utf8;
	m_password_utf8 = &password_utf8;
	m_password_prompt_enabled = &password_prompt_enabled;
	m_is_identity_query = is_identity_query;

	if (*m_password_prompt_enabled == true)
	{
		m_username_password_io_ptr->iPasswordPromptEnabled = ETrue; 
	}
	else
	{
		m_username_password_io_ptr->iPasswordPromptEnabled = EFalse; 
	}

	if (m_is_identity_query == true)
	{
		m_username_password_io_ptr->iIsIdentityQuery = ETrue; 
	}
	else
	{
		m_username_password_io_ptr->iIsIdentityQuery = EFalse; 
	}


	eap_variable_data_c tmp_username_unicode(m_am_tools);
	status = m_am_tools->convert_utf8_to_unicode(tmp_username_unicode, *m_username_utf8);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_username_password_io_ptr->iUsername.Copy(
		reinterpret_cast<TUint16 *> (
		tmp_username_unicode.get_data(tmp_username_unicode.get_data_length())),
		tmp_username_unicode.get_data_length() / 2); // 8bit -> 16bit


	m_state = EHandlingUsernamePasswordQuery;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL(" eap_am_type_mschapv2_symbian_c::show_username_password_dialog - before m_notifier.StartNotifierAndGetResponse()\n")));		

	TInt err1 = KErrNone;

	TRAPD(err, err1 = IsDlgReadyToCompleteL());

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::show_username_password_dialog(): err=%d, result= %d\n"),
		err,
		err1));

	if (*m_password_prompt_enabled == true || err || err1 == KErrCancel)
	{
		TEapExpandedType aEapType(*EapExpandedTypeMsChapv2.GetType());
		m_username_password_io_ptr->iPassword.Zero();
		if (iEapAuthNotifier == 0)
		{
			TRAPD(err, iEapAuthNotifier = CEapAuthNotifier::NewL( *this ));
			if (err)
			{
				return eap_status_authentication_failure;
			}
		}
		else
		{
			iEapAuthNotifier->Cancel();
		}

		TRAPD(err1, iEapAuthNotifier->StartL(CEapAuthNotifier::EEapNotifierTypeMsChapV2UsernamePasswordDialog, m_username_password_io_ptr, aEapType));
		if (err1)
		{
			return eap_status_authentication_failure;
		}
	}
	else
	{
		DlgComplete( status );
		return status;	
	}

	return eap_status_pending_request;
}

//--------------------------------------------------

TInt eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL()
	{

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL(): m_index_type=%d, m_index=%d, m_tunneling_type=0xfe%06x%08x\n"),
		m_index_type,
		m_index,
		m_tunneling_type.get_vendor_id(),
		m_tunneling_type.get_vendor_type()));

	TInt status = KErrNone;
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	
	sqlStatement.Format(
		KSQLQuery,
		&cf_str_EAP_MSCHAPV2_password_prompt_literal,
		&cf_str_EAP_MSCHAPV2_username_literal,
		&cf_str_EAP_MSCHAPV2_password_literal,
		&KMsChapV2TableName,
		&KServiceType,
		m_index_type, 
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
	

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL(): Opens view\n")));

	RDbView view;
	// Evaluate view
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	// Get the first (and only) row
	view.FirstL();
	view.GetL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_leap_symbian_c::IsDlgReadyToCompleteL(): Reads database\n")));

	TPtrC username = view.ColDes(colSet->ColNo( cf_str_EAP_MSCHAPV2_username_literal ) );

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL(): username"),
		username.Ptr(),
		username.Size()));

	TPtrC password = view.ColDes(colSet->ColNo( cf_str_EAP_MSCHAPV2_password_literal ) );

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL(): password"),
		password.Ptr(),
		password.Size()));

	TUint prompt = view.ColUint(colSet->ColNo(cf_str_EAP_MSCHAPV2_password_prompt_literal));

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL(): prompt=%d\n"),
		prompt));


	if ((EEapDbFalse != prompt)
		 || (username.Size() == 0) 
		 || (password.Size() == 0))
		{

		if (username.Size() == 0)
			{
			m_username_password_io_ptr->iUsername.Zero();
			}
		else
			{
			m_username_password_io_ptr->iUsername.Copy(username);
			}

		status = KErrCancel;
		}
	else
		{
		status = KErrNone;	
		m_username_password_io_ptr->iUsername.Copy(username);
		m_username_password_io_ptr->iPassword.Copy(password);
		}
		
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.
		
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_mschapv2_symbian_c::IsDlgReadyToCompleteL(): status=%d\n"),
		status));

	return status;
	}
	
eap_status_e eap_am_type_mschapv2_symbian_c::show_change_password_dialog(
		eap_variable_data_c & /* username */,
		eap_variable_data_c & /* old_password */,
		eap_variable_data_c & /* password */,
		bool & /* password_prompt_enabled */)
{

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL(" eap_am_type_mschapv2_symbian_c::show_change_password_dialog - THIS IS NOT SUPPORTED - return eap_status_not_supported \n")));

#if !defined (EAP_MSCHAPV2_ENABLE_PASSWORD_CHANGE)

	send_error_notification(eap_status_password_expired);

	// This is not supported.
	return eap_status_not_supported;

#else
	
	// Don't remove this. May be needed in future.

	m_username_utf8 = &username;
	m_password_utf8 = &password;
	m_old_password_utf8 = &old_password;
	m_password_prompt_enabled = &password_prompt_enabled;




	return eap_status_pending_request;
	
#endif	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::read_auth_failure_string(eap_mschapv2_error_e error_code, eap_variable_data_c &string)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_UNREFERENCED_PARAMETER(error_code);
	EAP_UNREFERENCED_PARAMETER(string);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_mschapv2_symbian_c::get_memory_store_key(
	eap_variable_data_c * const memory_store_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = memory_store_key->set_copy_of_buffer(
		EAP_MSCHAPV2_CREDENTIAL_HANDLE_KEY,
		sizeof(EAP_MSCHAPV2_CREDENTIAL_HANDLE_KEY));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u8_t fill = ':';

	status = memory_store_key->add_data(
		&m_index_type,
		sizeof(m_index_type));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = memory_store_key->add_data(
		&fill,
		sizeof(fill));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = memory_store_key->add_data(
		&m_index,
		sizeof(m_index));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	status = memory_store_key->add_data(
		&fill,
		sizeof(fill));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		u32_t vendor_id = m_tunneling_type.get_vendor_id();

		status = memory_store_key->add_data(
			&vendor_id,
			sizeof(vendor_id));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		u32_t vendor_type = m_tunneling_type.get_vendor_type();
		status = memory_store_key->add_data(
			&vendor_type,
			sizeof(vendor_type));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

bool eap_am_type_mschapv2_symbian_c::is_session_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	bool sessionValidity(false);
	
	TRAPD(err, sessionValidity = is_session_validL());
	if (err != KErrNone) 
	{
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_mschapv2_symbian_c::is_session_valid - LEAVE - error=%d, Assuming session is invalid \n"),
			err));
			
		sessionValidity = false;
	}
	 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return sessionValidity;
}

//--------------------------------------------------

bool eap_am_type_mschapv2_symbian_c::is_session_validL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_mschapv2_symbian_c::is_session_valid - start \n")));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&cf_str_EAP_MSCHAPv2_max_session_validity_time_literal,
		&KMSCHAPv2LastFullAuthTime,
		&KMsChapV2TableName,
		&KServiceType,
		m_index_type, 
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

	RDbView view;
	// Evaluate view
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement)));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Get the first (and only) row
	view.FirstL();
	view.GetL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
		
	TInt64 maxSessionTime = view.ColInt64(colSet->ColNo(cf_str_EAP_MSCHAPv2_max_session_validity_time_literal));
	TInt64 fullAuthTime = view.ColInt64(colSet->ColNo(KMSCHAPv2LastFullAuthTime));

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.
	
	// If the max session time from DB is zero then we use the 
	// one read from configuration file.
	
	if( maxSessionTime == 0)
	{
		EAP_TRACE_DEBUG(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("Session Validity - Using max session validity time from config file\n")));
	
		maxSessionTime = m_max_session_time; // value from configuration file.
	}
	
	// Get the current time.
	TTime currentTime;
	currentTime.UniversalTime();
	
	TTime lastFullAuthTime(fullAuthTime);
	
#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
		
	TDateTime fullAuthDateTime = lastFullAuthTime.DateTime();

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("Session Validity - Current Time,        %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1, currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("Session Validity - Last Full Auth Time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	fullAuthDateTime.Day()+1, fullAuthDateTime.Month()+1, fullAuthDateTime.Year(), fullAuthDateTime.Hour(),
	fullAuthDateTime.Minute(), fullAuthDateTime.Second(), fullAuthDateTime.MicroSecond()));

#endif

	TTimeIntervalMicroSeconds interval = currentTime.MicroSecondsFrom(lastFullAuthTime);
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_mschapv2_symbian_c::is_session_valid:interval in microseconds:"),
			&(interval.Int64()),
			sizeof(interval.Int64()) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_mschapv2_symbian_c::is_session_valid:max session time in microseconds:"),
			&(maxSessionTime),
			sizeof(maxSessionTime) ) );
			
	
#if defined(_DEBUG) || defined(DEBUG)

	TTimeIntervalMinutes intervalMins;
	TInt error = currentTime.MinutesFrom(lastFullAuthTime, intervalMins);
	
	if(error == KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_mschapv2_symbian_c::is_session_validL()")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
	}
	
#endif


	if( maxSessionTime >= interval.Int64() )
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_mschapv2_symbian_c::is_session_valid - Session Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			

		return true;	
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_mschapv2_symbian_c::is_session_valid - Session NOT Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
		
		return false;	
	}
}

//--------------------------------------------------

eap_status_e eap_am_type_mschapv2_symbian_c::store_authentication_time()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	eap_status_e status(eap_status_ok);
	
	TRAPD(err, store_authentication_timeL());
	if (err != KErrNone) 
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
	}
	 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_mschapv2_symbian_c::store_authentication_timeL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_mschapv2_symbian_c::store_authentication_timeL - start \n")));	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KMSCHAPv2LastFullAuthTime,
		&KMsChapV2TableName,
		&KServiceType,
		m_index_type, 
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

	RDbView view;
	// Evaluate view
	User::LeaveIfError(view.Prepare(m_database, TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());
	
	// Get the first (and only) row for updation.
	view.FirstL();
	view.UpdateL();
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Get the current universal time.
	TTime currentTime;
	currentTime.UniversalTime();
		
#if defined(_DEBUG) || defined(DEBUG)	
	
	TDateTime currentDateTime = currentTime.DateTime();
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
	(EAPL("eap_am_type_mschapv2_symbian_c::store_authentication_time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

#endif

	TInt64 fullAuthTime = currentTime.Int64();
	
	view.SetColL(colSet->ColNo(KMSCHAPv2LastFullAuthTime), fullAuthTime);

	view.PutL();	

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
}

//--------------------------------------------------
// End of Files
