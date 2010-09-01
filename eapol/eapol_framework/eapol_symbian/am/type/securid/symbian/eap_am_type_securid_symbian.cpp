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
* %version: 32 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 311 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include <coemain.h>
#include <bautils.h>
#include <barsc.h>

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_type_securid_symbian.h"
#include "EapSecurIDDbParameterNames.h"
#include "EapSecurIDDbUtils.h"
#include "EapSecurIDNotifierStructs.h"
#include "EapGtcDbParameterNames.h"
#include "EapGtcDbUtils.h"
#include "EapSecurIDNotifierUids.h"
#include "eap_configuration_field.h"
#include "eap_state_notification.h"

#include "eap_am_trace_symbian.h"

const TUint KMaxSqlQueryLength = 256;
const TUint KMaxDBFieldNameLength = 255;
const char EAP_GTC_USERNAME_HANDLE_KEY[] = "eap_type_securid_c GTC username";
const TInt 	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMicroSecsInASecond = 1000000; // 1000000 micro seconds is 1 second.

// ================= MEMBER FUNCTIONS =======================

EAP_FUNC_EXPORT eap_am_type_securid_symbian_c::~eap_am_type_securid_symbian_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_securid_symbian_c::~eap_am_type_securid_symbian_c(): this = 0x%08x\n"),
		this));

	EAP_ASSERT(m_shutdown_was_called == true);	

	m_database.Close();
	m_session.Close();

	delete m_dialog_data_ptr;
	delete m_dialog_data_pckg_ptr;
	delete m_message_buf;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_securid_symbian_c::shutdown(): this = 0x%08x\n"),
		this));

	if( IsActive() )
	{
		Cancel(); // Cancel only if active.
	}  
	else
	{
		if( m_is_notifier_connected )
		{
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - calling m_notifier.CancelNotifier(..)\n")));
	
			TInt error = m_notifier.CancelNotifier(KEapSecurIDIdentityQueryUid);
			
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - CancelNotifier(KEapSecurIDIdentityQueryUid) error=%d\n"), error));


			error = m_notifier.CancelNotifier(KEapSecurIDPasscodeQueryUid);
			
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - CancelNotifier(KEapSecurIDPasscodeQueryUid) error=%d\n"), error));


			error = m_notifier.CancelNotifier(KEapSecurIDPincodeQueryUid);
			
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - CancelNotifier(KEapSecurIDPincodeQueryUid) error=%d\n"), error));


			error = m_notifier.CancelNotifier(KEapGtcIdentityQueryUid);
			
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - CancelNotifier(KEapGtcIdentityQueryUid) error=%d\n"), error));


			error = m_notifier.CancelNotifier(KEapGtcUserInputQueryUid);
			
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - CancelNotifier(KEapGtcUserInputQueryUid) error=%d\n"), error));


	
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::shutdown - calling m_notifier.Close(), prev error=%d\n"), error));

			m_notifier.Close(); // Call close only if it is connected.	
			
			m_is_notifier_connected = false;
		}
	}
	
	m_shutdown_was_called = true;

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_securid_symbian_c::shutdown(): this = 0x%08x returns\n"),
		this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

eap_am_type_securid_symbian_c::eap_am_type_securid_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
		: CActive(CActive::EPriorityStandard)
		, eap_am_type_securid_c(tools /*, partner */)
		, m_state(EHandlingIdentityQuery)
		, m_am_tools(tools)
		, m_partner(partner)
		, m_receive_network_id(tools)
		, m_index_type(aIndexType)
		, m_index(aIndex)
		, m_tunneling_type(aTunnelingType)
		, m_is_client(aIsClient)
		, m_is_valid(false)
		, m_shutdown_was_called(false)
		, m_eap_type(aEapType)
		, m_is_notifier_connected(false)
		, m_max_session_time(0)	
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#ifdef USE_EAP_EXPANDED_TYPES

	m_tunneling_vendor_type = m_tunneling_type.get_vendor_type();
	m_eap_vendor_type = m_eap_type.get_vendor_type();

#else

	m_tunneling_vendor_type = static_cast<TUint>(m_tunneling_type);
	m_eap_vendor_type = static_cast<TUint>(m_eap_type);	

#endif //#ifdef USE_EAP_EXPANDED_TYPES

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

eap_am_type_securid_symbian_c* eap_am_type_securid_symbian_c::NewL(
	abs_eap_am_tools_c * const aTools,
	abs_eap_base_type_c * const aPartner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const eap_type_value_e aEapType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
{
	eap_am_type_securid_symbian_c * self = new(ELeave) eap_am_type_securid_symbian_c(
		aTools, 
		aPartner, 
		aIndexType, 
		aIndex, 
		aTunnelingType, 
		aEapType,
		aIsClient,
		receive_network_id);

	CleanupStack::PushL(self);

	if (self->get_is_valid() != true)
	{
		User::Leave(KErrGeneral);
	}

	self->ConstructL();

	CleanupStack::Pop();

	return self;
}

//--------------------------------------------------

void eap_am_type_securid_symbian_c::ConstructL()
{
	// Open/create database
	if (m_eap_type == eap_type_generic_token_card)
	{
		EapGtcDbUtils::OpenDatabaseL(m_database, m_session, m_index_type, m_index, m_tunneling_type);
	}
	else
	{
		EapSecurIDDbUtils::OpenDatabaseL(m_database, m_session, m_index_type, m_index, m_tunneling_type);
	}

	m_dialog_data_ptr = new(ELeave) TEapSecurIDStruct;
	m_dialog_data_pckg_ptr = new(ELeave) TPckg<TEapSecurIDStruct> (*m_dialog_data_ptr);

	CActiveScheduler::Add(this);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_securid_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_type_securid_symbian_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

void eap_am_type_securid_symbian_c::send_error_notification(const eap_status_e error)
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
		m_eap_type,
		eap_state_none,
		general_state_variable,
		0,
		false);

	notification.set_authentication_error(error);

	m_partner->state_notification(&notification);
}

//--------------------------------------------------

void eap_am_type_securid_symbian_c::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);		
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_securid_symbian_c::RunL - start")
		 EAPL("m_state, iStatus.Int()=%d\n"),
		 m_state, iStatus.Int()));

	if (iStatus.Int() == KErrCancel)
	{
		delete m_message_buf;
		m_message_buf = NULL;
		get_am_partner()->finish_unsuccessful_authentication(true);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;
	}
	
	if (iStatus.Int() != KErrNone)
	{
		delete m_message_buf;
		m_message_buf = NULL;
		// Something is very wrong...

		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP - SecurID notifier or dialog\n")));

		send_error_notification(eap_status_authentication_failure);

		get_am_partner()->finish_unsuccessful_authentication(false);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;
	}

	switch (m_state)
	{
	case EHandlingIdentityQuery:
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c::RunL(): EHandlingIdentityQuery\n")));

			eap_variable_data_c identity(m_am_tools);

			eap_status_e status = identity.set_copy_of_buffer(
				m_dialog_data_ptr->iIdentity.Ptr(),
				m_dialog_data_ptr->iIdentity.Size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			eap_variable_data_c identity_utf8(m_am_tools);
			status = m_am_tools->convert_unicode_to_utf8(identity_utf8, identity);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			status = get_am_partner()->complete_eap_identity_query(&identity_utf8);
		}
		break;

	case EHandlingPasscodeQuery:
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c::RunL(): EHandlingPasscodeQuery\n")));

			eap_variable_data_c passcode(m_am_tools);

			eap_status_e status = passcode.set_copy_of_buffer(
				m_dialog_data_ptr->iPasscode.Ptr(),
				m_dialog_data_ptr->iPasscode.Size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			eap_variable_data_c passcode_utf8(m_am_tools);
			status = m_am_tools->convert_unicode_to_utf8(passcode_utf8, passcode);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			status = get_am_partner()->client_securid_complete_passcode_query(&passcode_utf8);
		}
		break;

	case EHandlingPincodeQuery:
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c::RunL(): EHandlingPincodeQuery\n")));

			eap_variable_data_c pincode(m_am_tools);

			eap_status_e status = pincode.set_copy_of_buffer(
				m_dialog_data_ptr->iPincode.Ptr(),
				m_dialog_data_ptr->iPincode.Size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			eap_variable_data_c passcode(m_am_tools);

			status = passcode.set_copy_of_buffer(
				m_dialog_data_ptr->iPasscode.Ptr(),
				m_dialog_data_ptr->iPasscode.Size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}


			eap_variable_data_c pincode_utf8(m_am_tools);
			status = m_am_tools->convert_unicode_to_utf8(pincode_utf8, pincode);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			eap_variable_data_c passcode_utf8(m_am_tools);
			status = m_am_tools->convert_unicode_to_utf8(passcode_utf8, passcode);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			status = get_am_partner()->client_securid_complete_pincode_query(&passcode_utf8, &passcode_utf8);
		}
		break;

	case EHandlingGTCQuery:
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c::RunL(): EHandlingGTCQuery\n")));

			delete m_message_buf;
			m_message_buf = NULL;

			eap_variable_data_c passcode(m_am_tools);

			eap_status_e status = passcode.set_copy_of_buffer(
				m_dialog_data_ptr->iPasscode.Ptr(),
				m_dialog_data_ptr->iPasscode.Size());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}

			eap_variable_data_c passcode_utf8(m_am_tools);
			status = m_am_tools->convert_unicode_to_utf8(passcode_utf8, passcode);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
				(void)EAP_STATUS_RETURN(m_am_tools, status);
				return;
			}
			
			// User must have entered some password and pressed OK.
			// Treat this as a full authentication and update the Last Auth Time.
			status = store_authentication_time();
			if (status != eap_status_ok)
			{
				// Storing failed. Don't care.
				EAP_TRACE_ERROR(m_am_tools, 
					TRACE_FLAGS_DEFAULT, (
					EAPL("eap_am_type_securid_symbian_c:Storing Last Full Authentication time failed, status=%d, but continuing\n"), 
					status));

				status = eap_status_ok;
			}			

			status = get_am_partner()->client_gtc_complete_user_input_query(&passcode_utf8);
		}
		break;

	default:
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: EAP - SecurID illegal state in RunL.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return;		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

void eap_am_type_securid_symbian_c::DoCancel()
{
	if( m_is_notifier_connected )
	{
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::DoCancel - calling m_notifier.CancelNotifier(..)\n")));
		
		TInt error = m_notifier.CancelNotifier(KEapSecurIDIdentityQueryUid);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::DoCancel - CancelNotifier(KEapSecurIDIdentityQueryUid) error=%d\n"), error));

		error = m_notifier.CancelNotifier(KEapSecurIDPasscodeQueryUid);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::DoCancel - CancelNotifier(KEapSecurIDPasscodeQueryUid) error=%d\n"), error));

		error = m_notifier.CancelNotifier(KEapSecurIDPincodeQueryUid);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::DoCancel - CancelNotifier(KEapSecurIDPincodeQueryUid) error=%d\n"), error));

		error = m_notifier.CancelNotifier(KEapGtcIdentityQueryUid);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::DoCancel - CancelNotifier(KEapGtcIdentityQueryUid) error=%d\n"), error));

		error = m_notifier.CancelNotifier(KEapGtcUserInputQueryUid);
		
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::DoCancel - CancelNotifier(KEapGtcUserInputQueryUid) error=%d\n"), error));

		m_notifier.Close(); // Call close only if it is connected.	
		
		m_is_notifier_connected = false;
	}
}

//--------------------------------------------------


EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::type_configure_read(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT(data != 0);
	// Trap must be set here because the OS independent portion of EAP SecurID
	// that calls this function does not know anything about Symbian.	
	eap_status_e status(eap_status_ok);
	TRAPD(err, type_configure_readL(
		field->get_field(),
		field->get_field_length(),
		data));
	if (err != KErrNone) 
	{
		// Read is routed to partner object, for reading from configuration file.
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

void eap_am_type_securid_symbian_c::type_configure_readL(
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

	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	if (m_eap_type == eap_type_securid)
	{
		sqlStatement.Format(KSQLQueryRow, &unicodeString, &KSecurIDTableName, 
			&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	}
	else
	{
		sqlStatement.Format(KSQLQueryRow, &unicodeString, &KGtcTableName, 
			&KServiceType, m_index_type, &KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	}	
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

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::type_configure_write(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	// NOTE: At the moment this is not called anywhere.
	// NOTE: This is really just for simulation.
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			data);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	{
		// Read Maximum Session Validity Time from the config file
		eap_variable_data_c sessionTimeFromFile(m_am_tools);
		
		eap_status_e status = m_partner->read_configure(
			cf_str_EAP_GTC_max_session_validity_time.get_field(),
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

EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::reset()
{
	return eap_status_ok;
}

//--------------------------------------------------

eap_status_e eap_am_type_securid_symbian_c::show_identity_query_dialog(
	eap_type_value_e eap_type,
	eap_variable_data_c * const identity)
{
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (
		EAPL("eap_am_type_securid_symbian_c::show_identity_query_dialog()\n")));
		
	EAP_UNREFERENCED_PARAMETER(eap_type);
	EAP_UNREFERENCED_PARAMETER(identity);
	
	// This function gets called only if the identity (username) is missing from the 
	// user configuration. Probably user/device management hasn't configured it.
	
	EAP_TRACE_ERROR(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("ERROR: EAP - SecurID - No Identity (username) \n")));

	send_error_notification(eap_status_identity_query_failed);
	
	return eap_status_identity_query_failed;
}

//--------------------------------------------------

eap_status_e eap_am_type_securid_symbian_c::show_passcode_query_dialog(
	eap_variable_data_c * const /*passcode*/,
	bool is_first_query)
{
	if (!IsActive())
	{
		m_state = EHandlingPasscodeQuery;
		
		if (is_first_query == true)
		{
			m_dialog_data_ptr->iIsFirstQuery = ETrue;
		}
		else
		{
			m_dialog_data_ptr->iIsFirstQuery = EFalse;
		}

		if( !m_is_notifier_connected )
		{
			TInt error = m_notifier.Connect();
			
			EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::show_passcode_query_dialog - m_notifier.Connect() returned error=%d\n"), error));
			
			if( error != KErrNone)
			{
				// Can not connect to notifier.
				return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));		
			}
			
			m_is_notifier_connected = true; // Got connectted to notifier.
		}

		EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::show_passcode_query_dialog - StartNotifierAndGetResponse - KEapSecurIDPasscodeQueryUid \n")));

		m_notifier.StartNotifierAndGetResponse(
			iStatus, 
			KEapSecurIDPasscodeQueryUid, 
			*m_dialog_data_pckg_ptr, 
			*m_dialog_data_pckg_ptr);

		SetActive();
	} 
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c: Already active when tried to show passcode query dialog.\n")));
		return eap_status_process_general_error;
	}

	return eap_status_pending_request;
}

//--------------------------------------------------

eap_status_e eap_am_type_securid_symbian_c::show_gtc_query_dialog(
	eap_variable_data_c * const /*passcode*/,
	const u8_t * const message,
	u32_t message_length,
	bool is_first_query)
{
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_securid_symbian_c::show_gtc_query_dialog: message"),
		message,
		message_length));

	if (!IsActive())
	{
		m_state = EHandlingGTCQuery;

		eap_variable_data_c message_utf8(m_am_tools);
		eap_status_e status = message_utf8.set_buffer(message, message_length, false, false);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c message_unicode(m_am_tools);
		status = m_am_tools->convert_utf8_to_unicode(message_unicode, message_utf8);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		TRAPD(err, m_message_buf = HBufC8::NewL(message_unicode.get_data_length()));
		if (err != KErrNone)
		{
			return eap_status_allocation_error;
		}
		TPtr8 messageBufPtr = m_message_buf->Des();
		messageBufPtr.Copy(message_unicode.get_data(), message_unicode.get_data_length());

		if (is_first_query == true)
		{
			m_dialog_data_ptr->iIsFirstQuery = ETrue;
		}
		else
		{
			m_dialog_data_ptr->iIsFirstQuery = EFalse;
		}
		
		EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::show_gtc_query_dialog - before m_notifier.Connect(), m_is_notifier_connected=%d\n"), m_is_notifier_connected));

		if( !m_is_notifier_connected )
		{
			TInt error = m_notifier.Connect();
			
			EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::show_gtc_query_dialog - m_notifier.Connect() returned error=%d\n"), error));
			
			if( error != KErrNone)
			{
				// Can not connect to notifier.
				return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));		
			}
			
			m_is_notifier_connected = true; // Got connectted to notifier.
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_securid_symbian_c::show_gtc_query_dialog: m_message_buf"),
			m_message_buf->Ptr(),
			m_message_buf->Size()));

		m_notifier.StartNotifierAndGetResponse(
			iStatus, 
			KEapGtcUserInputQueryUid, 
			*m_message_buf, 
			*m_dialog_data_pckg_ptr);

		SetActive();
	} 
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c: Already active when tried to show GTC query dialog.\n")));
		return eap_status_process_general_error;
	}

	return eap_status_pending_request;
}

//--------------------------------------------------

eap_status_e eap_am_type_securid_symbian_c::show_pincode_query_dialog(
	eap_variable_data_c * const /*passcode*/,
	eap_variable_data_c * const /*pincode*/,
	bool is_first_query)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::_pincode_query_dialog - start - is_first_query=%d\n"), is_first_query));
	
	if (!IsActive())
	{
		m_state = EHandlingPincodeQuery;

		if (is_first_query == true)
		{
			m_dialog_data_ptr->iIsFirstQuery = ETrue;
		}
		else
		{
			m_dialog_data_ptr->iIsFirstQuery = EFalse;
		}

		if( !m_is_notifier_connected )
		{
			TInt error = m_notifier.Connect();
			
			EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::show_pincode_query_dialog - m_notifier.Connect() returned error=%d\n"), error));
			
			if( error != KErrNone)
			{
				// Can not connect to notifier.
				return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));		
			}
			
			m_is_notifier_connected = true; // Got connectted to notifier.
		}

		EAP_TRACE_DEBUG_SYMBIAN((_L(" eap_am_type_securid_symbian_c::show_pincode_query_dialog - StartNotifierAndGetResponse - KEapSecurIDPincodeQueryUid \n")));

		m_notifier.StartNotifierAndGetResponse(
			iStatus, 
			KEapSecurIDPincodeQueryUid, 
			*m_dialog_data_pckg_ptr, 
			*m_dialog_data_pckg_ptr);

		SetActive();
	} 
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c: Already active when tried to show identity query dialog.\n")));
		return eap_status_process_general_error;
	}

	return eap_status_pending_request;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::read_auth_failure_string(
	eap_variable_data_c * const string)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_UNREFERENCED_PARAMETER(string);

	eap_status_e status=eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_securid_symbian_c::get_memory_store_key(
	eap_variable_data_c * const memory_store_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = memory_store_key->set_copy_of_buffer(
		EAP_GTC_USERNAME_HANDLE_KEY,
		sizeof(EAP_GTC_USERNAME_HANDLE_KEY));
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

	status = memory_store_key->add_data(
		&m_tunneling_vendor_type,
		sizeof(m_tunneling_vendor_type));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

bool eap_am_type_securid_symbian_c::is_session_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	bool sessionValidity(false);
	
	TRAPD(err, sessionValidity = is_session_validL());
	if (err != KErrNone) 
	{
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_securid_symbian_c::is_session_valid - LEAVE - error=%d, Assuming session is invalid \n"),
			err));
			
		sessionValidity = false;
	}
	 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return sessionValidity;
}

//--------------------------------------------------

bool eap_am_type_securid_symbian_c::is_session_validL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (
		EAPL("eap_am_type_securid_symbian_c::is_session_valid: EAP vendor type=%d\n"),
		m_eap_vendor_type));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	if (m_eap_type == eap_type_generic_token_card)
	{
		sqlStatement.Format(KSQLQuery, &cf_str_EAP_GTC_max_session_validity_time_literal,
							&KGTCLastFullAuthTime, &KGtcTableName,
							&KServiceType, m_index_type, 
							&KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	}
	else
	{
		// Secure ID is not supported at the moment.
		// Treat this as session invalid.

		CleanupStack::PopAndDestroy(buf); // Delete buf.
		return false;		
	}
	

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
		
	TInt64 maxSessionTime = view.ColInt64(colSet->ColNo(cf_str_EAP_GTC_max_session_validity_time_literal));
	TInt64 fullAuthTime = view.ColInt64(colSet->ColNo(KGTCLastFullAuthTime));

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
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_securid_symbian_c::is_session_valid:interval in microseconds:"),
			&(interval.Int64()),
			sizeof(interval.Int64()) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_securid_symbian_c::is_session_valid:max session time in microseconds:"),
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
			(EAPL("eap_am_type_securid_symbian_c::is_session_validL()")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
	}
	
#endif


	if( maxSessionTime >= interval.Int64() )
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c::is_session_valid - Session Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			

		return true;	
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_securid_symbian_c::is_session_valid - Session NOT Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
		
		return false;	
	}
}

//--------------------------------------------------

eap_status_e eap_am_type_securid_symbian_c::store_authentication_time()
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

void eap_am_type_securid_symbian_c::store_authentication_timeL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, 
		TRACE_FLAGS_DEFAULT, (
		EAPL("eap_am_type_securid_symbian_c::store_authentication_timeL: EAP Vendor Type=%d\n"),
		m_eap_vendor_type));	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	if (m_eap_type == eap_type_generic_token_card)
	{
		sqlStatement.Format(KSQLQuery, &KGTCLastFullAuthTime, &KGtcTableName,
							&KServiceType, m_index_type, 
							&KServiceIndex, m_index, &KTunnelingType, m_tunneling_vendor_type);
	}
	else
	{
		// Secure ID is not supported at the moment.
		// Leave with error.

		CleanupStack::PopAndDestroy(buf); // Delete buf.
		User::Leave(KErrNotSupported);		
	}
		
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
	(EAPL("eap_am_type_securid_symbian_c::store_authentication_time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

#endif

	TInt64 fullAuthTime = currentTime.Int64();
	
	view.SetColL(colSet->ColNo(KGTCLastFullAuthTime), fullAuthTime);

	view.PutL();	

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
}

//--------------------------------------------------
// End of File
