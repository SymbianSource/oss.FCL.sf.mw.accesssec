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
* %version: 46.1.11 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 604 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

// INCLUDE FILES

#include "eap_tools.h"
#include "eap_am_type_aka_symbian.h"
#include "eap_am_tools_symbian.h"
#include "eap_state_notification.h"
#include "EapAkaDbDefaults.h"
#include "EapAkaDbParameterNames.h"
#include "EapAkaDbUtils.h"
#include "EapTraceSymbian.h"

#include <d32dbms.h>	// For DBMS
#include <s32strm.h> 	// For RReadStream

#if defined (USE_EAP_TYPE_SERVER_AKA)
// These are needed only for the server and test environment (Plugin tester)
// Enable USE_EAP_TYPE_SERVER_AKA in eapol.mmh to build for test environment.
#include "eap_crypto_api.h"
#include "eap_am_aka_milenage_algorithm.h"
#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)

#if defined (USE_EAP_AKA_INTERFACE) && !defined(__WINS__)
	#include "EapAkaInterface.h"	
#endif // End of #if defined (USE_EAP_AKA_INTERFACE) && !defined(__WINS__)

// This is needed for cf_str_EAP_AKA_2_digit_mnc_map_of_mcc_of_imsi_array.
#include "eap_type_aka_types.h"

const TUint AKA_IMSI_LENGTH = 15u;
const TUint KMaxSqlQueryLength = 512;
const TUint KMaxDBFieldNameLength = 255;
const TInt 	KDefaultColumnInView_One = 1; // For DB view.
const TInt 	KMicroSecsInASecond = 1000000; // 1000000 micro seconds is 1 second.

const u8_t EAP_AKA_DEFAULT_REAUTHENTICATION_REALM[] = "dymmy.reauth.org";
const u32_t EAP_AKA_DEFAULT_REAUTHENTICATION_REALM_LENGTH = sizeof(EAP_AKA_DEFAULT_REAUTHENTICATION_REALM)-1ul;

#if defined (USE_EAP_TYPE_SERVER_AKA) || defined(__WINS__)

const char TEST_IMSI[] = "244070100000001";

#endif

#if defined (USE_EAP_TYPE_SERVER_AKA)
// For the server side.

struct eap_aka_encryption_imsi_block_s
{
	u8_t id_type:1;
	u8_t imsi_length:7;
	u8_t imsi_and_padding[AKA_IMSI_LENGTH];
};

struct eap_aka_pseudonym_s
{
	u32_t encryption_key_index;
	union _IV
	{
		u8_t IV_8[EAP_AES_BLOCK_SIZE];
		u32_t IV_32[EAP_AES_BLOCK_SIZE/sizeof(u32_t)];
	} encryption_IV;

	eap_aka_encryption_imsi_block_s imsi_block;

	u8_t MAC[HMAC_SHA1_128_SIZE];
};

const u32_t ENCRYPTION_KEY_INDEX_SCRAMBLE_CONST = 0xa7b3c922;

#endif //#if defined (USE_EAP_TYPE_SERVER_AKA)

// ================= MEMBER FUNCTIONS =======================


eap_am_type_aka_symbian_c::eap_am_type_aka_symbian_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
: eap_am_type_aka_c(tools)
, m_am_tools(static_cast<eap_am_tools_symbian_c*>(tools)) // Tools class must be of type eap_am_tools_symbian because
														  // this is Symbian specific code.
, m_partner(partner)
, m_nai_realm(tools)
, m_index_type(aIndexType)
, m_index(aIndex)
, m_tunneling_type(aTunnelingType)
, m_is_valid(false)
, m_is_client(aIsClient)
, m_stored_reauth_id(tools)
, m_stored_pseudonym(tools)
, m_previous_imsi(tools)
, m_stored_required_completion(eap_type_aka_complete_none)
, m_stored_received_eap_identifier(0)
, m_shutdown_was_called(false)
, m_aka_algorithm(0)
, m_aka_if(0)
, m_simulator_aka_K(tools)
, m_simulator_aka_OP(tools)
, m_simulator_aka_AMF(tools)
, m_authentication_vector(0)
, m_pseudonym_identity(tools)
, m_reauthentication_identity(tools)
, m_username(tools)
, m_receive_network_id(tools)
, m_IMSI(tools)
, m_required_identity(aka_payload_NONE)
, m_required_completion(eap_type_aka_complete_none)
, m_identity_type(AKA_IDENTITY_TYPE_NONE)
, m_completion_action(eap_type_aka_complete_none)
, m_next_eap_identifier(0)
, m_aka_authentication_vector_status(eap_aka_authentication_vector_status_ok)
, m_pseudonym_key_index(0u)
, m_pseudonym_key(tools)
, m_pseudonym_MAC_key(tools)
, m_prev_pseudonym_key(tools)
, m_prev_pseudonym_MAC_key(tools)
, m_pseudonym_key_use_count(0u)
, m_RAND(tools)
, m_AUTN(tools)
, m_max_session_time(0)
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

void eap_am_type_aka_symbian_c::ConstructL()
{

#if defined (USE_EAP_TYPE_SERVER_AKA)

	// For the server.
	m_aka_algorithm = new eap_am_aka_milenage_algorithm_c(m_am_tools, m_is_client);
	if (m_aka_algorithm == 0
		|| m_aka_algorithm->get_is_valid() == false)
	{
		if (m_aka_algorithm != 0)
		{
			m_aka_algorithm->shutdown();
		}
		delete m_aka_algorithm;
		m_aka_algorithm = 0;
		return;
	}
#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)	

	TInt error = m_session.Connect();
	EAP_TRACE_DEBUG_SYMBIAN((_L("eap_am_type_aka_symbian_c::ConstructL(): - m_session.Connect(), error=%d\n"), error));
	User::LeaveIfError(error);

	// Open/create database
	EapAkaDbUtils::OpenDatabaseL(m_database, m_session, m_index_type, m_index, m_tunneling_type);	
		
	// SIM IMSI, RES, CK, IK and AUTS are queried from SIM using AKA interface. 
	// If this is not used then Nokia test algorithms and test values are used.
#if defined (USE_EAP_AKA_INTERFACE)	&& !defined(__WINS__)
	if (m_is_client == true)
	{
		m_aka_if = CEapAkaInterface::NewL(m_am_tools, this);
	} 
	else
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: EAP-AKA server does not work at the moment in plugintester.\n")));
		User::Leave(KErrNotSupported);
	}
#endif //#if defined (USE_EAP_AKA_INTERFACE)	&& !defined(__WINS__)
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_type_aka_symbian_c* eap_am_type_aka_symbian_c::NewL(
	abs_eap_am_tools_c * const aTools,
	abs_eap_base_type_c * const aPartner,
	const TIndexType aIndexType,
	const TInt aIndex,
	const eap_type_value_e aTunnelingType,
	const bool aIsClient,
	const eap_am_network_id_c * const receive_network_id)
{
	eap_am_type_aka_symbian_c* self = new eap_am_type_aka_symbian_c(
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

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_type_aka_symbian_c::~eap_am_type_aka_symbian_c()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_type_aka_symbian_c::~eap_am_type_aka_symbian_c(): this = 0x%08x\n"),
		this));

	m_database.Close();
	m_session.Close();

#if defined(USE_EAP_AKA_INTERFACE) && !defined(__WINS__)
	if (m_is_client == true)
	{
		delete m_aka_if;
	}
#endif

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::configure()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_AKA_manual_realm.get_field(),
			&m_nai_realm);
		if (status == eap_status_ok
			&& m_nai_realm.get_is_valid_data() == true)
		{
			// OK NAI realm configured.
		}
		else
		{
			// No NAI realm configured.
			// Lets use dummy.
			status = m_nai_realm.set_copy_of_buffer(EAP_AKA_DEFAULT_REAUTHENTICATION_REALM,
				EAP_AKA_DEFAULT_REAUTHENTICATION_REALM_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Read Maximum Session Validity Time from the config file
		eap_variable_data_c sessionTimeFromFile(m_am_tools);
		
		eap_status_e status = type_configure_read(
			cf_str_EAP_AKA_max_session_validity_time.get_field(),
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

#if defined (USE_EAP_TYPE_SERVER_AKA)

	// We have to set the values for K, OP and AMF in simulator.
	
	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_AKA_simulator_aka_k.get_field(),
			&m_simulator_aka_K);
		if (status == eap_status_ok
			&& m_simulator_aka_K.get_is_valid_data() == true
			&& m_simulator_aka_K.get_data_length() > 0ul
			&& m_simulator_aka_K.get_data(
				m_simulator_aka_K.get_data_length()) != 0)
		{
			// OK.
			eap_status_e status = m_aka_algorithm->set_simulator_aka_k(&m_simulator_aka_K);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: illegal configuration value %s\n"),
				 cf_str_EAP_AKA_simulator_aka_k.get_field()->get_field()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}

	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_AKA_simulator_aka_op.get_field(),
			&m_simulator_aka_OP);
		if (status == eap_status_ok
			&& m_simulator_aka_OP.get_is_valid_data() == true
			&& m_simulator_aka_OP.get_data_length() > 0ul
			&& m_simulator_aka_OP.get_data(
				m_simulator_aka_OP.get_data_length()) != 0)
		{
			// OK.
			eap_status_e status = m_aka_algorithm->set_simulator_aka_op(&m_simulator_aka_OP);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: illegal configuration value %s\n"),
				 cf_str_EAP_AKA_simulator_aka_op.get_field()->get_field()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}

	{
		eap_status_e status = type_configure_read(
			cf_str_EAP_AKA_simulator_aka_amf.get_field(),
			&m_simulator_aka_AMF);
		if (status == eap_status_ok
			&& m_simulator_aka_AMF.get_is_valid_data() == true
			&& m_simulator_aka_AMF.get_data_length() == sizeof(u16_t)
			&& m_simulator_aka_AMF.get_data(
				m_simulator_aka_AMF.get_data_length()) != 0)
		{
			// OK.
			eap_status_e status = m_aka_algorithm->set_simulator_aka_amf(&m_simulator_aka_AMF);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: illegal configuration value %s\n"),
				 cf_str_EAP_AKA_simulator_aka_amf.get_field()->get_field()));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}	

	if (m_pseudonym_key.get_is_valid_data() == false)
	{
		crypto_aes_c aes(m_am_tools);

		if (aes.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Note this function generates cryptographically strong random bytes.
		// Here we use those bytes as a secret encryption key.
		eap_status_e status = generate_encryption_IV(
			&m_pseudonym_key,
			aes.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = generate_encryption_IV(
			&m_pseudonym_MAC_key,
			aes.get_block_size());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		++m_pseudonym_key_index;
	}

#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::reset()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("%s: eap_am_type_aka_symbian_c::shutdown(), m_shutdown_was_called=%d\n"),
		(m_is_client == true) ? "client": "server",
		m_shutdown_was_called));

	if (m_shutdown_was_called == true)
	{
		// Shutdown function was called already.
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
	m_shutdown_was_called = true;
	
	
	if (m_aka_algorithm != 0)
	{
		m_aka_algorithm->shutdown();
		delete m_aka_algorithm;
		m_aka_algorithm = 0;
	}	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::send_error_notification(const eap_status_e error)
{
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
		eap_type_aka,
		eap_state_none,
		eap_general_state_authentication_error,
		0,
		false);

	notification.set_authentication_error(error);

	m_partner->state_notification(&notification);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::store_pseudonym_id(
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const pseudonym)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Send error if the pseudonym is too long.
	if(pseudonym != NULL && pseudonym->get_data_length() > KMaxPseudonymIdLengthInDB)
	{
		// Pseudonym too long. Can't store this in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_aka_symbian_c::store_pseudonym_id: ")
			 EAPL("Too long Pseudonym. Length=%d\n"),
			 pseudonym->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	eap_status_e status(eap_status_ok);

	TRAPD(err, store_pseudonym_idL(send_network_id, pseudonym));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::store_pseudonym_idL(
	const eap_am_network_id_c * const /*network_id*/,
	const eap_variable_data_c * const pseudonym)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KPseudonymId,
		&KAkaTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());

	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	// Update the columns in the database
	view.FirstL();
	view.UpdateL();	
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();		
	CleanupStack::PushL(colSet);
	
	// Create pointer to the data
	if ((pseudonym != NULL) 
		&& (pseudonym->get_is_valid_data() == true))
	{		
		TPtrC8 pseudonymId(
			pseudonym->get_data(pseudonym->get_data_length()),
			pseudonym->get_data_length());
				
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("pseudonymId to DB"),
			pseudonymId.Ptr(),
			pseudonymId.Length()));
		
		view.SetColL(colSet->ColNo(KPseudonymId), pseudonymId);		
	} 
	else 
	{
		// If passed pseudonym was 0 that means the field must be cleared.
		view.SetColNullL(colSet->ColNo(KPseudonymId));
	}

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	
	view.PutL();
	
	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::store_reauthentication_id(
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const reauthentication_identity)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Send error if the reauthentication id is too long.
	if(reauthentication_identity != NULL 
		&& reauthentication_identity->get_data_length() > KMaxReauthIdLengthInDB)
	{
		// Reauth id too long. Can't store this in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_aka_symbian_c::store_reauthentication_id: ")
			 EAPL("Too long reauth id. Length=%d\n"),
			 reauthentication_identity->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
		
	eap_status_e status(eap_status_ok);

	TRAPD(err, store_reauthentication_idL(send_network_id, reauthentication_identity));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::store_reauthentication_idL(
	const eap_am_network_id_c * const /*network_id*/,
	const eap_variable_data_c * const reauthentication_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KReauthId,
		&KAkaTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	view.FirstL();

	view.UpdateL();

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Create pointer to the data
	if ((reauthentication_id != NULL) 
		&& (reauthentication_id->get_is_valid_data() == true))
	{
		TPtrC8 reauthId(
			reauthentication_id->get_data(reauthentication_id->get_data_length()), 
			reauthentication_id->get_data_length());

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("reauthId to DB"),
			reauthId.Ptr(),
			reauthId.Length()));
		
		view.SetColL(colSet->ColNo(KReauthId), reauthId);
		
	} 
	else 
	{
		// If passed reauthentication_id was 0 that means the field must be cleared.
		view.SetColNullL(colSet->ColNo(KReauthId));
	}

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	
	view.PutL();	
		
	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::store_reauth_parameters(
	const eap_variable_data_c * const XKEY,
	const eap_variable_data_c * const K_aut,
	const eap_variable_data_c * const K_encr,
	const u32_t reauth_counter)
{
	// These kind of wrapper functions are needed because the Symbian L-functions must be executed in 
	// trap harness.
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Send error if any of the parameters are invalid.
	if(XKEY == NULL 
		|| K_aut == NULL
		|| K_encr == NULL)
	{
		// Some of the parameters are invalid.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_aka_symbian_c::store_reauth_parameters: ")
			 EAPL("ERROR: Invalid parameters\n")));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	// Send error if any of the parameters are too long.
	if(XKEY->get_data_length() > KMaxXKeyLengthInDB 
		|| K_aut->get_data_length() > KMaxK_autLengthInDB 
		|| K_encr->get_data_length() > KMaxK_encrLengthInDB )
	{
		// Some of the parameters are too long. Can't store them in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_aka_symbian_c::store_reauth_parameters: ")
			 EAPL("Too long parameters. Length: XKEY=%d, K_aut=%d, K_encr=%d\n"),
			 XKEY->get_data_length(), K_aut->get_data_length(), K_encr->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_ok);

	TRAPD(err, store_reauth_parametersL(XKEY, K_aut, K_encr, reauth_counter));
	if (err != KErrNone)
	{
		// Convert the leave error code to EAPOL stack error code.
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::store_reauth_parametersL(
	const eap_variable_data_c * const XKEY,
	const eap_variable_data_c * const K_aut,
	const eap_variable_data_c * const K_encr,
	const u32_t reauth_counter)
{	
	// The _L functions do the actual thing.
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KXKey,
		&KK_aut,
		&KK_encr,
		&KReauthCounter,
		&KAkaTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	// Create pointers to the data
	TPtrC8 key(XKEY->get_data(XKEY->get_data_length()), XKEY->get_data_length());
	TPtrC8 aut(K_aut->get_data(K_aut->get_data_length()), K_aut->get_data_length());
	TPtrC8 enc(K_encr->get_data(K_encr->get_data_length()), K_encr->get_data_length());
	
	// Update the columns in the database
	view.FirstL();	
	view.UpdateL();

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("XKEY to DB"), key.Ptr(),	key.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_aut to DB"), aut.Ptr(),	aut.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_encr to DB"), enc.Ptr(),	enc.Length()));
	
	view.SetColL(colSet->ColNo(KXKey), key); // XKEY
	view.SetColL(colSet->ColNo(KK_aut), aut); // K_aut
	view.SetColL(colSet->ColNo(KK_encr), enc); // K_encr
	view.SetColL(colSet->ColNo(KReauthCounter), reauth_counter); // ReauthCounter

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.

	view.PutL();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_aka_symbian_c::store_reauth_keys_L(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 reauth_counter));

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::authentication_finished(
	const bool true_when_successfull,
	const eap_aka_authentication_type_e authentication_type,
	const eap_type_aka_identity_type identity_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);
	
	TInt err(KErrNone);	

	// Store the authentication time if the full authentication is successful
	if (true_when_successfull == true
		&& authentication_type == AKA_AUTHENTICATION_TYPE_FULL_AUTH)
	{
		TRAP(err,store_authentication_timeL());
		if (err != KErrNone)
		{
			status = m_am_tools->convert_am_error_to_eapol_error(err);
			send_error_notification(status);
		}
	}

	if (true_when_successfull == false)
	{
		if( identity_type == AKA_IDENTITY_TYPE_IMSI_ID 
			|| identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID )
		{
			(void) store_pseudonym_id(0,0);
		}
		
		if( identity_type == AKA_IDENTITY_TYPE_IMSI_ID 
			|| identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID )
		{
			(void) store_reauthentication_id(0,0);			
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_reauth_parameters(
	eap_variable_data_c * const XKEY,
	eap_variable_data_c * const K_aut,
	eap_variable_data_c * const K_encr,
	u32_t * const reauth_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	eap_status_e status(eap_status_ok);

	TRAPD(err, query_reauth_parametersL(XKEY, K_aut, K_encr, reauth_counter));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::query_reauth_parametersL(
	eap_variable_data_c * const XKEY,
	eap_variable_data_c * const reauth_K_aut,
	eap_variable_data_c * const reauth_K_encr,
	u32_t * const reauth_counter)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query
	_LIT(KSQLQuery, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KXKey,
		&KK_aut,
		&KK_encr,
		&KReauthCounter,
		&KAkaTableName, 
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

	// Get the values from DB
	TPtrC8 key = view.ColDes8(colSet->ColNo(KXKey));	
	TPtrC8 aut = view.ColDes8(colSet->ColNo(KK_aut));
	TPtrC8 enc = view.ColDes8(colSet->ColNo(KK_encr));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("XKEY from DB"), key.Ptr(),	key.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_aut from DB"), aut.Ptr(),	aut.Length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("K_encr from DB"), enc.Ptr(),	enc.Length()));
					
	eap_status_e status(eap_status_process_general_error);
	
	// Store the values to the supplied buffers
	status = XKEY->set_copy_of_buffer(key.Ptr(),key.Length());
	if (status != eap_status_ok)
	{
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}

	status = reauth_K_aut->set_copy_of_buffer(aut.Ptr(),aut.Length());
	if (status != eap_status_ok)
	{
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}

	status = reauth_K_encr->set_copy_of_buffer(enc.Ptr(),enc.Length());	
	if (status != eap_status_ok)
	{
		User::Leave(
			m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status)));
	}
	
	*reauth_counter = view.ColUint(colSet->ColNo(KReauthCounter));

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_aka_symbian_c::query_reauth_parametersL(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 *reauth_counter));

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::increase_reauth_counter()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_ok);

	TRAPD(err, increase_reauth_counterL());
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::increase_reauth_counterL()
{
	// Form the insertion command
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KReauthCounter,
		&KAkaTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	
	view.FirstL();
	view.GetL();

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
	
	// Get the previous value
	TUint counter = view.ColUint(colSet->ColNo(KReauthCounter));

	view.UpdateL();
	
	// Increment the value
	view.SetColL(colSet->ColNo(KReauthCounter), counter + 1); 

	counter = view.ColUint(colSet->ColNo(KReauthCounter));
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_type_aka_symbian_c::increase_reauth_counterL(): %s, m_saved_reauth_counter %d.\n"),
		 (m_is_client == true ? "client": "server"),
		 counter));

	view.PutL();

	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_AKA_IMSI_or_pseudonym_or_reauthentication_id(
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const reauthentication_identity,
	eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	u32_t * const /*length_of_mnc*/,
	const aka_payload_AT_type_e required_identity, ///< This parameter indicated the type of identity required.
	const eap_type_aka_complete_e required_completion, ///< This parameter tells the required completion after this call is completed, if this is asyncronous. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
	const u8_t received_eap_identifier ///< This is the EAP-identifier of the received EAP-request message. Use this value with abs_eap_am_type_aka_c::complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query() function call.
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	EAP_ASSERT((IMSI != 0) && (pseudonym_identity != 0) && (reauthentication_identity != 0));

	m_stored_required_completion = required_completion;
	m_stored_received_eap_identifier = received_eap_identifier;

	TRAPD(err, query_AKA_IMSI_or_pseudonym_or_reauthentication_idL(IMSI,
																 pseudonym_identity,
																 reauthentication_identity,
																 automatic_realm,
																 required_identity,
																 required_completion,
																 received_eap_identifier));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);

		if (status != eap_status_pending_request)
		{
			send_error_notification(status);
		}
	} 

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::query_AKA_IMSI_or_pseudonym_or_reauthentication_idL(
	eap_variable_data_c * const IMSI,
	eap_variable_data_c * const pseudonym_identity,
	eap_variable_data_c * const reauthentication_identity,
	eap_variable_data_c * const automatic_realm, ///< If this is not used, do not add any data to this parameter.
	const aka_payload_AT_type_e required_identity,
	const eap_type_aka_complete_e /*required_completion*/,
	const u8_t /*received_eap_identifier*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_process_general_error);

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Reset everything
	IMSI->reset();
	pseudonym_identity->reset();
	reauthentication_identity->reset();
	automatic_realm->reset();
	m_stored_pseudonym.reset();
	m_stored_reauth_id.reset();
	m_previous_imsi.reset();

	_LIT(KSQLQuery, "SELECT %S, %S, %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KReauthId,
		&KReauthCounter,
		&KPseudonymId,
		&KPreviousIMSI,
		&KAkaTableName,
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
	
	// Get the values
	TUint reauthCount = view.ColUint32(colSet->ColNo(KReauthCounter));	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("query_AKA_IMSI_or_pseudonym_or_reauthentication_idL: ")
		 EAPL("required_identity=%d, reauthCount from DB %d\n"),
		 required_identity, reauthCount));
	
	// A stream is needed for LONG columns in DB.
	RDbColReadStream readStream;

	// Get pseudonym ID from DB.
	HBufC8* pseudonymIdBuf = HBufC8::NewLC(KMaxPseudonymIdLengthInDB); // Buffer for pseudonym id.
	TPtr8 pseudonymId = pseudonymIdBuf->Des();
	
	readStream.OpenLC(view, colSet->ColNo(KPseudonymId));
	readStream.ReadL(pseudonymId, view.ColLength(colSet->ColNo(KPseudonymId)));
	readStream.Close();
	CleanupStack::Pop(&readStream); // Pop readStream.
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("pseudonymId from DB"), pseudonymId.Ptr(), pseudonymId.Length()));

	// Get reauthentication ID from DB.
	HBufC8* reauthIdBuf = HBufC8::NewLC(KMaxReauthIdLengthInDB); // Buffer for reauthentication id.
	TPtr8 reauthId = reauthIdBuf->Des();
	
	readStream.OpenLC(view, colSet->ColNo(KReauthId));
	readStream.ReadL(reauthId, view.ColLength(colSet->ColNo(KReauthId)));
	readStream.Close();
	CleanupStack::Pop(&readStream); // Pop readStream.

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("reauthId from DB"), reauthId.Ptr(), reauthId.Length()));	
	
#if defined(USE_EAP_AKA_INTERFACE) && !defined(__WINS__)

	// Get the previous IMSI. Used for checking if SIM has been changed.
	// The checking is done in complete_AKA_imsi_L
	
	TPtrC8 tmp_imsi = view.ColDes8(colSet->ColNo(KPreviousIMSI));

	status = m_previous_imsi.set_copy_of_buffer(tmp_imsi.Ptr(), tmp_imsi.Length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		User::Leave(KErrNoMemory);
	}
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("imsi from DB"), tmp_imsi.Ptr(), tmp_imsi.Size()));
	
#endif
	
	if (required_identity == aka_payload_AT_ANY_ID_REQ)
	{
		if (is_session_valid() )
		{
			if(reauthId.Length() > 0)
			{
				
#if defined(USE_EAP_AKA_INTERFACE) && !defined(__WINS__)
				// Store the reauth id in case we are using asynchronous processing (= ISA interface)
				status = m_stored_reauth_id.set_copy_of_buffer(reauthId.Ptr(), reauthId.Length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(KErrNoMemory);
				}	
#endif
				status = reauthentication_identity->set_copy_of_buffer(reauthId.Ptr(), reauthId.Length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					User::Leave(KErrNoMemory);
				}	
			}
		}
	}

	CleanupStack::PopAndDestroy(reauthIdBuf); // Delete reauthIdBuf	
	
	if (required_identity == aka_payload_AT_ANY_ID_REQ
			|| required_identity == aka_payload_AT_FULLAUTH_ID_REQ)
	{
		if (pseudonymId.Length() > 0)
		{
			
#if defined(USE_EAP_AKA_INTERFACE) && !defined(__WINS__)
			// Store the pseudonym in case we are using
			// asynchronous processing (= ISA interface)
			status = m_stored_pseudonym.set_copy_of_buffer(
				pseudonymId.Ptr(),
				pseudonymId.Length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}
#endif
			status = pseudonym_identity->set_copy_of_buffer(
				pseudonymId.Ptr(),
				pseudonymId.Length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				User::Leave(KErrNoMemory);
			}
		}
	}

	CleanupStack::PopAndDestroy(pseudonymIdBuf); // Delete pseudonymIdBuf

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.

	CleanupStack::PopAndDestroy( &view ); // Close view.

	CleanupStack::PopAndDestroy(buf); // Delete buf

	if (IMSI->get_is_valid_data() == false
		|| IMSI->get_buffer_length() < AKA_IMSI_LENGTH)
	{
		status = IMSI->init(AKA_IMSI_LENGTH);
		if (status != eap_status_ok)
		{
			User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
		}

		IMSI->set_is_valid();
	}

	{
	
#if defined (USE_EAP_AKA_INTERFACE)	&& !defined(__WINS__)
	
		// For real AKA USIM interface.
		// Use real AKA interface active object.
		// This gets the IMSI from the real USIM, using Custom API.
		
		m_aka_if->QueryIMSIL();
		
		// KErrCompletion means that the operation is pending.
		User::Leave(KErrCompletion);

#elif defined(__WINS__) // For plugin tester.

		// Here we get the Nokia test SIM IMSI since the USIM interface is disabled.
		u32_t imsi_length = 0u;
		
		status = query_SIM_imsi(
			IMSI->get_buffer(AKA_IMSI_LENGTH),
			AKA_IMSI_LENGTH,
			&imsi_length);

		if (status != eap_status_ok
			|| imsi_length != AKA_IMSI_LENGTH)
		{			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrGeneral);
		}
		
		status = IMSI->set_data_length(imsi_length);

		if (status != eap_status_ok)
		{			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			User::Leave(KErrGeneral);
		}

#endif // End of #if defined (USE_EAP_AKA_INTERFACE)	&& !defined(__WINS__)
	
	}
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::complete_AKA_imsi_L(
	const eap_variable_data_c * const IMSI,
	const eap_status_e completion_status )
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_process_general_error);
	
	if (completion_status != eap_status_ok)
	{
		// IMSI query failed
		status = get_am_partner()->complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(
			IMSI, 
			&m_stored_pseudonym, 
			&m_stored_reauth_id, 
			0,
			EAP_TYPE_AKA_DEFAULT_MNC_LENGTH_3_BYTES,
			m_stored_required_completion, 
			m_stored_received_eap_identifier,
			completion_status);	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	if (IMSI == 0
		|| IMSI->get_is_valid_data() == false)
	{
		// IMSI query failed
		status = get_am_partner()->complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(
			IMSI, 
			&m_stored_pseudonym, 
			&m_stored_reauth_id, 
			0,
			EAP_TYPE_AKA_DEFAULT_MNC_LENGTH_3_BYTES,
			m_stored_required_completion, 
			m_stored_received_eap_identifier,
			eap_status_hardware_not_ready);	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	if (m_previous_imsi.get_data_length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Previous IMSI not valid. Storing new IMSI.\n")));

		// Store new IMSI
		status = store_imsi(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}		
	}
	else if (IMSI->compare(&m_previous_imsi) != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIM has been changed since last authentication. ")
			 EAPL("Clear pseudonym & reauth IDs.\n")));

		// Different IMSI -> SIM has been changed.
		// Reset pseudonym and reauthentication ID. 
		status = store_reauthentication_id(0, 0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = store_pseudonym_id(0, 0);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		// Store new IMSI
		status = store_imsi(IMSI);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		// Reset stored pseudonym & reauthentication ID
		m_stored_pseudonym.reset();
		m_stored_reauth_id.reset();
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("SIM has not been changed.\n")));
	}

	status = get_am_partner()->complete_AKA_IMSI_or_pseudonym_or_reauthentication_id_query(
		IMSI,
		&m_stored_pseudonym,
		&m_stored_reauth_id,
		0,
		0ul,
		m_stored_required_completion,
		m_stored_received_eap_identifier,
		eap_status_ok);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return status;
}

//--------------------------------------------------

eap_status_e eap_am_type_aka_symbian_c::store_imsi(
	const eap_variable_data_c * const imsi)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	
	
	// Send error if the IMSI is too long.
	if(imsi != NULL && imsi->get_data_length() > KMaxIMSILengthInDB)
	{
		// IMSI too long. Can't store this in DB.
		
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_aka_symbian_c::store_imsi: ")
			 EAPL("Too long IMSI. Length=%d\n"),
			 imsi->get_data_length()));
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_ok);

	TRAPD(err, store_imsiL(imsi));
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		send_error_notification(status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::store_imsiL(
	const eap_variable_data_c * const imsi)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Form the insertion command
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLInsert, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLInsert,
		&KPreviousIMSI,
		&KAkaTableName, 
		&KServiceType,
		m_index_type,
		&KServiceIndex,
		m_index,
		&KTunnelingTypeVendorId,
		m_tunneling_type.get_vendor_id(),
		&KTunnelingType, 
		m_tunneling_type.get_vendor_type());
		
	// Evaluate view
	RDbView view;
	
	User::LeaveIfError(view.Prepare(m_database,TDbQuery(sqlStatement), TDbWindow::EUnlimited));
	CleanupClosePushL(view);
	
	User::LeaveIfError(view.EvaluateAll());
	view.FirstL();

	view.UpdateL();

	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Create pointer to the data
	if ((imsi != 0) 
		&& (imsi->get_is_valid_data() == true))
	{
		TPtrC8 tmp_imsi(
			imsi->get_data(imsi->get_data_length()), 
			imsi->get_data_length());	
	
		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("IMSI to DB"), tmp_imsi.Ptr(), tmp_imsi.Length()));
		
		view.SetColL(colSet->ColNo(KPreviousIMSI), tmp_imsi); 
	} 
	else 
	{
		// If passed IMSI was 0 that means the field must be cleared.
		view.SetColNullL(colSet->ColNo(KPreviousIMSI));
	}
	
	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	
	view.PutL();	
	
	// Close database
	CleanupStack::PopAndDestroy(2); // view, buf

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::cancel_AKA_IMSI_or_pseudonym_or_reauthentication_id_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
#if defined (USE_EAP_AKA_INTERFACE) && !defined(__WINS__)
	if (m_is_client == true)
	{
		m_aka_if->Cancel();
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
#else
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_not_supported;
#endif
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_AKA_RES(
	eap_type_aka_authentication_vector_c * const authentication_vector)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// NOTE if user needs to use state_selector or n_rands after return from query_AKA_RES()
	// function those parameters MUST be copied using copy() member function of each parameter.
	// For example: saved_n_rands = n_rands->copy()

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	if (authentication_vector == 0
		|| authentication_vector->get_is_valid() == false)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	eap_status_e status = eap_status_process_general_error;

	if (authentication_vector->get_RAND()->get_is_valid_data() == false)
	{
		// No RAND. cannot continue.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	if (authentication_vector->get_AUTN()->get_is_valid_data() == false)
	{
		// No AUTN. cannot continue.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	
	// Update the member variables with current values for RAND and AUTN.
	// These are needed for synchronization failure.
	status = m_RAND.set_copy_of_buffer( authentication_vector->get_RAND() );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = 	m_AUTN.set_copy_of_buffer( authentication_vector->get_AUTN() );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}	
		
#if !defined (USE_EAP_AKA_INTERFACE)

	if (authentication_vector == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	status = m_aka_algorithm->generate_RES( authentication_vector );

#elif !defined(__WINS__)
	
	TRAPD(err, m_aka_if->QueryRESL( &m_RAND , &m_AUTN ); );	
	if (err != KErrNone)
	{
		status = m_am_tools->convert_am_error_to_eapol_error(err);
		if (status == eap_status_process_general_error)
		{
			status = eap_status_credential_query_failed;
		}
		send_error_notification(status);
	}
	else
	{
		status = eap_status_pending_request;
	}
#endif //#if !defined (USE_EAP_AKA_INTERFACE)
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::complete_AKA_RES_L(
	eap_variable_data_c * const aRES, 
	eap_variable_data_c * const aCK,
	eap_variable_data_c * const aIK,
	eap_variable_data_c * const aAUTS,
	eap_status_e authenticationStatus,
	const eap_status_e completion_status )	
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

#if !defined(USE_EAP_AKA_INTERFACE) || defined(__WINS__)

	EAP_UNREFERENCED_PARAMETER(aRES);
	EAP_UNREFERENCED_PARAMETER(aCK);
	EAP_UNREFERENCED_PARAMETER(aIK);
	EAP_UNREFERENCED_PARAMETER(aAUTS);
	EAP_UNREFERENCED_PARAMETER(authenticationStatus);
	EAP_UNREFERENCED_PARAMETER(completion_status);

#else

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("complete_AKA_RES_L\n")));

	eap_type_aka_authentication_vector_c  authentication_vector( m_am_tools );
	
	if (completion_status != eap_status_ok)
	{
		// Signal upper layer about the failure.
		status = get_am_partner()->complete_AKA_RES_query( &authentication_vector, completion_status);
		
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);		
	}	
	
	if (aRES == 0 || aRES->get_is_valid() == false ||
		aCK == 0 || aCK->get_is_valid() == false ||
		aIK == 0 || aIK->get_is_valid() == false ||
		aAUTS == 0 || aAUTS->get_is_valid() == false )
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
			
	status = authentication_vector.get_RES()->set_copy_of_buffer( aRES );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = authentication_vector.get_CK()->set_copy_of_buffer( aCK );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = authentication_vector.get_IK()->set_copy_of_buffer( aIK );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = authentication_vector.get_AUTS()->set_copy_of_buffer( aAUTS );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	// Copy RAND and AUTN also. They are needed in case of synchronization failure.
	
	status = authentication_vector.get_RAND()->set_copy_of_buffer( &m_RAND );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	status = authentication_vector.get_AUTN()->set_copy_of_buffer( &m_AUTN );
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}	
	
	authentication_vector.set_vector_status(authenticationStatus);

	// Complete request.
	status = get_am_partner()->complete_AKA_RES_query( &authentication_vector, eap_status_ok);
	
	if (status == eap_status_ok)
	{
		status = eap_status_completed_request;
	}
#endif	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::cancel_AKA_RES_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
#if defined (USE_EAP_AKA_INTERFACE) && !defined(__WINS__)
	if (m_is_client == true)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_aka_symbian_c::cancel_AKA_RES_query() - cancelling IF query\n")));
	
		m_aka_if->Cancel();
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
#else
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
#endif	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::handle_aka_notification(
	eap_aka_notification_codes_e aka_notification_code)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	switch ((aka_notification_code & aka_notification_code_value))
	{
	case eap_aka_notification_no_F_no_P_user_has_not_subscribed_to_the_requested_service:
		send_error_notification(eap_status_user_has_not_subscribed_to_the_requested_service);
		break;

	case eap_aka_notification_no_F_no_P_users_calls_are_barred:
		send_error_notification(eap_status_users_calls_are_barred);
		break;

	default:
		// Do nothing
		break;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_AKA_authentication_vector(
	const eap_variable_data_c * const username, ///< // This is payload AT_IDENTITY. If this is uninitialized then imsi must be initialized.
	const u8_t next_eap_identifier,
	eap_variable_data_c * const imsi, ///< This is the real IMSI. If this is uninitialized then username must be initialized and imsi will be initialized after this call.
	eap_type_aka_authentication_vector_c * const authentication_vector,
	eap_type_aka_identity_type * const type) 
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// NOTE if user needs to use state_selector or imsi after return from query_AKA_authentication_vector()
	// function those parameters MUST be copied using copy() member function of each parameter.
	// For example: saved_imsi = p_imsi_or_pseudonym->copy()
	//              saved_state_selector = state_selector->copy()

	eap_status_e status = eap_status_process_general_error;	
	
#if defined (USE_EAP_TYPE_SERVER_AKA) 

	if (username == 0
		|| imsi == 0
		|| authentication_vector == 0
		|| type == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (username->get_is_valid_data() == false
		&& imsi->get_is_valid_data() == false)
	{
		// Something is really wrong.
		// Only one of these must be set.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (username->get_is_valid_data() == true
		&& imsi->get_is_valid_data() == false)
	{
		// We must query IMSI.

		// This is akaple test.
		query_imsi_from_username_syncronous(
			0u,
			0,
			username,
			imsi,
			type);

		if (imsi->get_is_valid_data() == false
			|| imsi->get_data_length() != m_am_tools->strlen(TEST_IMSI)
			|| m_am_tools->memcmp(imsi->get_data(imsi->get_data_length()), TEST_IMSI, imsi->get_data_length()) != 0)
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: MAC of identity differs.\n")));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
	}
	else if (imsi->get_is_valid_data() == true)
	{
		*type = AKA_IDENTITY_TYPE_IMSI_ID;
	}

	{
		status = m_aka_algorithm->generate_authentication_vector(
			authentication_vector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("query_AKA_authentication_vector(): Used EAP-Identity type %d.\n"),
		*type));

	m_next_eap_identifier = next_eap_identifier;

	m_aka_authentication_vector_status = eap_aka_authentication_vector_status_ok;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("AKA: %s: direct_complete_function: complete_AKA_authentication_vector_query()\n"),
			(m_is_client == true ? "client": "server")));

		status = get_am_partner()->complete_AKA_authentication_vector_query(
			authentication_vector,
			imsi,
			m_aka_authentication_vector_status,
			*type,
			eap_status_ok,
			next_eap_identifier);
		if (status == eap_status_ok)
		{
			status = eap_status_completed_request;
		}
	}
#else

	EAP_UNREFERENCED_PARAMETER(username);
	EAP_UNREFERENCED_PARAMETER(next_eap_identifier);
	EAP_UNREFERENCED_PARAMETER(imsi);
	EAP_UNREFERENCED_PARAMETER(authentication_vector);
	EAP_UNREFERENCED_PARAMETER(type);	
	
#endif // #if !defined (USE_EAP_TYPE_SERVER_AKA)	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);		
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::cancel_AKA_authentication_vector_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

#if !defined (USE_EAP_TYPE_SERVER_AKA)

	EAP_TRACE_ERROR(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("cancel_AKA_authentication_vector_query()\n")));

	delete m_authentication_vector;
	m_authentication_vector = 0;

#endif // #if !defined (USE_EAP_TYPE_SERVER_AKA)	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::generate_encryption_IV(
	eap_variable_data_c * const encryption_IV,
	const u32_t IV_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	eap_status_e status = eap_status_process_general_error;
	
	status = encryption_IV->init(IV_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	encryption_IV->set_is_valid();
	encryption_IV->set_data_length(IV_length);

	m_am_tools->get_crypto()->add_rand_seed_hw_ticks();

	status = m_am_tools->get_crypto()->get_rand_bytes(
		encryption_IV->get_data(encryption_IV->get_data_length()),
		encryption_IV->get_data_length());
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);	
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::generate_pseudonym_id(
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const pseudonym_identity,
	const u32_t maximum_pseudonym_length)
{

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

#if defined (USE_EAP_TYPE_SERVER_AKA)
	
	// From AKA simulator code.
	// This is an example.

	return generate_identity(
		AKA_IDENTITY_TYPE_PSEUDONYM_ID,
		imsi,
		pseudonym_identity,
		maximum_pseudonym_length);
#else

	EAP_UNREFERENCED_PARAMETER(send_network_id);
	EAP_UNREFERENCED_PARAMETER(imsi);
	EAP_UNREFERENCED_PARAMETER(pseudonym_identity);
	EAP_UNREFERENCED_PARAMETER(maximum_pseudonym_length);	

	// This function shouldn't be called for other than server.
	return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
	
#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)		
		
}

//--------------------------------------------------

#if defined (USE_EAP_TYPE_SERVER_AKA)
	// These functions are used only for server side.

eap_status_e eap_am_type_aka_symbian_c::generate_identity(
	const eap_type_aka_identity_type identity_type,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const pseudonym,
	const u32_t maximum_pseudonym_length)
{

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	// From AKA simulator code.
	
	// This is an example.

	eap_status_e status = eap_status_process_general_error;

	//return eap_status_not_supported; // This will disable pseudonym and re-authentication idetities.

	// Here pseydonym indentity includes encrypted IMSI.
	// This causes the client to be database of it's own pseudonym identity.
	// Server stores only one or more global encryption key.
	// Encryption key is indexed by encryption_key_index attribute of pseudonym.
	// Server could store old keys some time after a new key is changed.
	//                                         
	// --------time------------>               
	//                                         
	// +---Key-1-------+                       
	//       +---Key-2------+                  
	//               +---Key-3------+          
	//                     +---Key-4------+
	//                                         

	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c encryption_IV(m_am_tools);

	{
		status = generate_encryption_IV(
			&encryption_IV,
			aes.get_block_size());
	}

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c tmp_pseudonym(m_am_tools);
	status = tmp_pseudonym.set_buffer_length(sizeof(eap_aka_pseudonym_s));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	tmp_pseudonym.set_data_length(sizeof(eap_aka_pseudonym_s));
	eap_aka_pseudonym_s * const str_pseudonym 
		= reinterpret_cast<eap_aka_pseudonym_s * const>(tmp_pseudonym.get_data(
			sizeof(eap_aka_pseudonym_s)));

	m_am_tools->memset(str_pseudonym, 0, sizeof(*str_pseudonym));

	str_pseudonym->imsi_block.imsi_length = static_cast<u8_t>(imsi->get_data_length());
	if (identity_type == AKA_IDENTITY_TYPE_PSEUDONYM_ID)
	{
		str_pseudonym->imsi_block.id_type = 0;
	}
	else if (identity_type == AKA_IDENTITY_TYPE_RE_AUTH_ID)
	{
		str_pseudonym->imsi_block.id_type = 1;
	}
	else
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	str_pseudonym->encryption_key_index = m_pseudonym_key_index;

	m_am_tools->memmove(
		str_pseudonym->encryption_IV.IV_8,
		encryption_IV.get_data(aes.get_block_size()),
		sizeof(str_pseudonym->encryption_IV.IV_8));
	m_am_tools->memmove(
		str_pseudonym->imsi_block.imsi_and_padding,
		imsi->get_data(imsi->get_data_length()),
		imsi->get_data_length());

	u32_t imsi_data_length = sizeof(u8_t)+imsi->get_data_length();

	u32_t cbc_aes_data_length = 0u;
	if ((imsi_data_length % aes.get_block_size()) != 0u)
	{
		cbc_aes_data_length = imsi_data_length + (aes.get_block_size() - (aes.get_block_size() % imsi_data_length));
	}
	else
	{
		cbc_aes_data_length = imsi_data_length;
	}

	u32_t padding_bytes_length = cbc_aes_data_length - imsi_data_length;

	if (padding_bytes_length > 0u)
	{
		cbc_aes.add_padding_bytes(
			&(str_pseudonym->imsi_block.imsi_and_padding[str_pseudonym->imsi_block.imsi_length]),
			padding_bytes_length,
			0ul);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym struct"),
		reinterpret_cast<u8_t *>(str_pseudonym),
		sizeof(*str_pseudonym)));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym IV"),
		encryption_IV.get_data(encryption_IV.get_data_length()),
		encryption_IV.get_data_length()));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym encryption key"),
		m_pseudonym_key.get_data(m_pseudonym_key.get_data_length()),
		m_pseudonym_key.get_data_length()));

	status = cbc_aes.set_encryption_key(
		encryption_IV.get_data(encryption_IV.get_data_length()),
		encryption_IV.get_data_length(),
		m_pseudonym_key.get_data(m_pseudonym_key.get_data_length()),
		m_pseudonym_key.get_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = cbc_aes.encrypt_data(
		&(str_pseudonym->imsi_block),
		sizeof(str_pseudonym->imsi_block));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		crypto_sha1_c sha1(m_am_tools);
		crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);
	  
		if (hmac_sha1.get_is_valid() == false)
	    {
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	    }

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym MAC key"),
			m_pseudonym_MAC_key.get_data(m_pseudonym_MAC_key.get_data_length()),
			m_pseudonym_MAC_key.get_data_length()));

		if (hmac_sha1.hmac_set_key(
			&m_pseudonym_MAC_key
			) != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		hmac_sha1.hmac_update(
			reinterpret_cast<u8_t *>(str_pseudonym),
			sizeof(*str_pseudonym)-sizeof(str_pseudonym->MAC));

		u32_t length = EAP_TYPE_AKA_MAC_SIZE;

		hmac_sha1.hmac_128_final(
			str_pseudonym->MAC,
			&length);

		EAP_ASSERT(length == EAP_TYPE_AKA_MAC_SIZE);
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym data"),
		tmp_pseudonym.get_data(tmp_pseudonym.get_data_length()),
		tmp_pseudonym.get_data_length()));

	// NOTE this does not add any security.
	// This will only scramble encryption key index.
	str_pseudonym->encryption_key_index ^= 
		(str_pseudonym->encryption_IV.IV_32[0]
		+ str_pseudonym->encryption_IV.IV_32[1]
		+ str_pseudonym->encryption_IV.IV_32[2]
		+ str_pseudonym->encryption_IV.IV_32[3]
		+ ENCRYPTION_KEY_INDEX_SCRAMBLE_CONST);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym data"),
		tmp_pseudonym.get_data(tmp_pseudonym.get_data_length()),
		tmp_pseudonym.get_data_length()));

	pseudonym->init(3ul+(sizeof(*str_pseudonym)+1u)*4u/3u);
	pseudonym->set_is_valid();
	pseudonym->set_data_length(pseudonym->get_buffer_length());

	u32_t pseudonym_length = pseudonym->get_data_length();

	status = m_am_tools->convert_bytes_to_ascii_armor(
		tmp_pseudonym.get_data_offset(0u, tmp_pseudonym.get_data_length()),
		tmp_pseudonym.get_data_length(),
		pseudonym->get_data_offset(0u, pseudonym->get_data_length()),
		&pseudonym_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (pseudonym_length > maximum_pseudonym_length)
	{
		pseudonym_length = maximum_pseudonym_length;
	}
	pseudonym->set_data_length(pseudonym_length);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym"),
		pseudonym->get_data(pseudonym->get_data_length()),
		pseudonym->get_data_length()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

eap_status_e eap_am_type_aka_symbian_c::query_imsi_from_username_syncronous(
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const network_id,
	const eap_variable_data_c * const username,
	eap_variable_data_c * const imsi,
	eap_type_aka_identity_type * const identity_type)
{
	// Note this is syncronous call.
	if (network_id == 0
		|| username == 0
		|| imsi == 0
		|| identity_type == 0)
	{
		// Something is really wrong.
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	crypto_aes_c aes(m_am_tools);
	crypto_cbc_c cbc_aes(m_am_tools, &aes, false);

	if (cbc_aes.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_process_general_error;

	const u8_t * const username_prefix = username->get_data_offset(0u, 1u);

	if (username->get_data_length() <= AKA_IMSI_LENGTH+1u
		&& username->get_data_length() > 1u
		&& username_prefix != 0
		&& *username_prefix == *AKA_IMSI_PREFIX_CHARACTER
		&& check_is_valid_imsi(username) == eap_status_ok)
	{
		// We have IMSI.
		status = imsi->set_copy_of_buffer(
			username->get_data_offset(1u, username->get_data_length()-1u),
			username->get_data_length()-1u);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		*identity_type = AKA_IDENTITY_TYPE_IMSI_ID;

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IMSI"),
			imsi->get_data(imsi->get_data_length()),
			imsi->get_data_length()));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("query_imsi_from_username(): Used EAP-Identity type %d.\n"),
			*identity_type));

		status = eap_status_ok;
	}
	else if (username->get_data_length() > aes.get_block_size()
			 && username->get_data_length() > sizeof(eap_aka_pseudonym_s))
	{
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("username"),
			username->get_data(username->get_data_length()),
			username->get_data_length()));

		// We have pseudonym_identity.
		eap_variable_data_c tmp_imsi(m_am_tools);
		tmp_imsi.set_buffer_length(sizeof(eap_aka_pseudonym_s)+1u);
		tmp_imsi.set_data_length(sizeof(eap_aka_pseudonym_s)+1u);
		u32_t tmp_imsi_length = tmp_imsi.get_data_length();

		eap_aka_pseudonym_s * const str_pseudonym = reinterpret_cast<eap_aka_pseudonym_s * const>(tmp_imsi.get_data_offset(0u, tmp_imsi.get_data_length()));
		if (str_pseudonym == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = m_am_tools->restore_bytes_from_ascii_armor(
			username->get_data_offset(0u, username->get_data_length()),
			username->get_data_length(),
			tmp_imsi.get_data_offset(0u, tmp_imsi.get_data_length()),
			&tmp_imsi_length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		tmp_imsi.set_data_length(tmp_imsi_length);

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym data"),
			tmp_imsi.get_data(tmp_imsi.get_data_length()),
			tmp_imsi.get_data_length()));

		// NOTE this does not add any security.
		// This will only scramble encryption key index.
		str_pseudonym->encryption_key_index ^= 
			(str_pseudonym->encryption_IV.IV_32[0]
			+ str_pseudonym->encryption_IV.IV_32[1]
			+ str_pseudonym->encryption_IV.IV_32[2]
			+ str_pseudonym->encryption_IV.IV_32[3]
			+ ENCRYPTION_KEY_INDEX_SCRAMBLE_CONST);

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym data"),
			tmp_imsi.get_data(tmp_imsi.get_data_length()),
			tmp_imsi.get_data_length()));

		status = eap_status_illegal_eap_identity;

		if ((m_pseudonym_key_index == str_pseudonym->encryption_key_index
			|| m_pseudonym_key_index-1u == str_pseudonym->encryption_key_index)
			&& tmp_imsi.get_data_length() == sizeof(eap_aka_pseudonym_s))
		{
			const eap_variable_data_c *test_pseudonym_key = &m_pseudonym_key;
			const eap_variable_data_c *test_pseudonym_MAC_key = &m_pseudonym_MAC_key;

			if (m_pseudonym_key_index-1u == str_pseudonym->encryption_key_index)
			{
				test_pseudonym_key = &m_prev_pseudonym_key;
				test_pseudonym_MAC_key = &m_prev_pseudonym_MAC_key;
			}

			{
				crypto_sha1_c sha1(m_am_tools);
				crypto_hmac_c hmac_sha1(m_am_tools, &sha1, false);

				if (hmac_sha1.get_is_valid() == false)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym MAC key"),
					test_pseudonym_MAC_key->get_data(test_pseudonym_MAC_key->get_data_length()),
					test_pseudonym_MAC_key->get_data_length()));

				if (hmac_sha1.hmac_set_key(
					test_pseudonym_MAC_key
					) != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				}

				hmac_sha1.hmac_update(
					reinterpret_cast<u8_t *>(str_pseudonym),
					sizeof(*str_pseudonym)-sizeof(str_pseudonym->MAC));

				u32_t length = EAP_TYPE_AKA_MAC_SIZE;
				u8_t tmp_MAC[EAP_TYPE_AKA_MAC_SIZE];

				hmac_sha1.hmac_128_final(
					tmp_MAC,
					&length);

				EAP_ASSERT(length == EAP_TYPE_AKA_MAC_SIZE);

				if (m_am_tools->memcmp(tmp_MAC, str_pseudonym->MAC, EAP_TYPE_AKA_MAC_SIZE) != 0)
				{
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: MAC of identity differs.\n")));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
				}
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym decryption key"),
				test_pseudonym_key->get_data(test_pseudonym_key->get_data_length()),
				test_pseudonym_key->get_data_length()));

			status = cbc_aes.set_decryption_key(
				str_pseudonym->encryption_IV.IV_8,
				sizeof(str_pseudonym->encryption_IV.IV_8),
				test_pseudonym_key->get_data(test_pseudonym_key->get_data_length()),
				test_pseudonym_key->get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = cbc_aes.decrypt_data(
				&(str_pseudonym->imsi_block),
				sizeof(str_pseudonym->imsi_block));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("pseudonym struct"),
				reinterpret_cast<u8_t *>(str_pseudonym),
				sizeof(*str_pseudonym)));

			u32_t imsi_length = static_cast<u32_t>(str_pseudonym->imsi_block.imsi_length);

			if (imsi_length < 0u
				|| imsi_length > AKA_IMSI_LENGTH)
			{
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: IMSI length illegal.\n")));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
			}

			if (str_pseudonym->imsi_block.id_type == 0)
			{
				*identity_type = AKA_IDENTITY_TYPE_PSEUDONYM_ID;
			}
			else if (str_pseudonym->imsi_block.id_type == 1)
			{
				*identity_type = AKA_IDENTITY_TYPE_RE_AUTH_ID;
			}
			else
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
			}



			status = imsi->set_copy_of_buffer(
				str_pseudonym->imsi_block.imsi_and_padding,
				imsi_length);

			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IMSI"),
				imsi->get_data(imsi->get_data_length()),
				imsi->get_data_length()));

			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("query_imsi_from_username(): Used EAP-Identity type %d.\n"),
				*identity_type));

			if (m_pseudonym_key_use_count < MAX_PSEUDONYM_USE_COUNT+MAX_REAUTH_USE_COUNT)
			{
				++m_pseudonym_key_use_count;
			}
			else
			{
				{
					crypto_aes_c aes(m_am_tools);

					if (aes.get_is_valid() == false)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					// Note this function generates cryptographically strong random bytes.
					// Here we use those bytes as a secret encryption key.
					eap_status_e status = m_prev_pseudonym_key.set_copy_of_buffer(&m_pseudonym_key);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					status = generate_encryption_IV(
						&m_pseudonym_key,
						aes.get_block_size());
					if (status == eap_status_ok)
					{
						status = m_prev_pseudonym_MAC_key.set_copy_of_buffer(&m_pseudonym_MAC_key);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
						status = generate_encryption_IV(
							&m_pseudonym_MAC_key,
							aes.get_block_size());
						if (status == eap_status_ok)
						{
						}
					}
					++m_pseudonym_key_index;
					m_pseudonym_key_use_count = 0u;
				}
			}
		}
		else
		{
			if (m_pseudonym_key_index != str_pseudonym->encryption_key_index)
			{
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: MAC key index differs, %lu != %lu.\n"),
					m_pseudonym_key_index,
					str_pseudonym->encryption_key_index));
			}
			else if (tmp_imsi.get_data_length() == sizeof(eap_aka_pseudonym_s))
			{
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: pseudonym length differs, %lu != %lu.\n"),
					tmp_imsi.get_data_length(),
					sizeof(eap_aka_pseudonym_s)));
			}

			status = eap_status_illegal_eap_identity;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("WARNING: illegal username.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_illegal_eap_identity;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)		

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::generate_reauthentication_id(
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const imsi,
	eap_variable_data_c * const reauthentication_identity,
	const u32_t maximum_reauthentication_identity_length)
{
	// From AKA simulator code.
	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// This is an example.

	eap_status_e status = eap_status_process_general_error;

#if defined (USE_EAP_TYPE_SERVER_AKA)

	status = generate_identity(
		AKA_IDENTITY_TYPE_RE_AUTH_ID,
		imsi,
		reauthentication_identity,
		maximum_reauthentication_identity_length);
	if (status != eap_status_ok)
	{
		reauthentication_identity->reset();
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	if (m_nai_realm.get_is_valid_data() == true
		&& m_nai_realm.get_data_length() > 0ul)
	{
		status = reauthentication_identity->add_data(reinterpret_cast<const u8_t * const>(AKA_AT_CHARACTER), 1u);
		if (status != eap_status_ok)
		{
			reauthentication_identity->reset();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = reauthentication_identity->add_data(&m_nai_realm);
		if (status != eap_status_ok)
		{
			reauthentication_identity->reset();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
#else

	EAP_UNREFERENCED_PARAMETER(send_network_id);
	EAP_UNREFERENCED_PARAMETER(imsi);
	EAP_UNREFERENCED_PARAMETER(reauthentication_identity);
	EAP_UNREFERENCED_PARAMETER(maximum_reauthentication_identity_length);	

#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}
	
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_imsi_from_username(
	const u8_t next_eap_identifier,
	const eap_am_network_id_c * const send_network_id,
	const eap_variable_data_c * const username,
	eap_variable_data_c * const imsi,
	eap_type_aka_identity_type * const type,
	const eap_type_aka_complete_e completion_action)
{
	// From AKA simulator code.

	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	// Note this is asyncronous call.
	
	eap_status_e status = eap_status_process_general_error;

#if defined (USE_EAP_TYPE_SERVER_AKA)

	m_identity_type = AKA_IDENTITY_TYPE_NONE;
	m_next_eap_identifier = 0;
	m_completion_action = eap_type_aka_complete_none;
	m_username.reset();
	m_IMSI.reset();

	status = query_imsi_from_username_syncronous(
		next_eap_identifier,
		send_network_id,
		username,
		imsi,
		type);
	if (status != eap_status_ok)
	{
		// Do not return immediately.
		// Here we test the asyncronous completion.
	}

	{
		status = get_am_partner()->complete_imsi_from_username(
			next_eap_identifier,
			send_network_id,
			username,
			imsi,
			*type,
			eap_status_ok,
			completion_action);

		if (status == eap_status_ok)
		{
			status = eap_status_completed_request;
		}
	}
#else

	EAP_UNREFERENCED_PARAMETER(next_eap_identifier);
	EAP_UNREFERENCED_PARAMETER(send_network_id);
	EAP_UNREFERENCED_PARAMETER(username);
	EAP_UNREFERENCED_PARAMETER(imsi);
	EAP_UNREFERENCED_PARAMETER(type);	
	EAP_UNREFERENCED_PARAMETER(completion_action);
	
#endif // #if defined (USE_EAP_TYPE_SERVER_AKA)

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, status);
}	

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_re_syncronization(
	const u8_t /*next_eap_identifier*/,
	eap_type_aka_authentication_vector_c * const /*authentication_vector*/
	)
{
	/********** For server.**********/
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::cancel_imsi_from_username_query()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::type_configure_read(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT(data != 0);

	eap_status_e status(eap_status_ok);
	
	// Trap must be set here because the OS independent portion of EAP AKA
	// that calls this function does not know anything about Symbian.	
	TRAPD(err, type_configure_readL(
		field->get_field(),
		field->get_field_length(),
		data));
	if (err != KErrNone)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_type_aka_symbian_c::type_configure_read(): LEAVE from type_configure_readL, error=%d, Reads configuration from partner.\n"),
			err));
	
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

void eap_am_type_aka_symbian_c::type_configure_readL(
	eap_config_string field,
	const u32_t field_length,
	eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(field_length);
	
	// Create a buffer for the ascii strings - initialised with the argument
	HBufC8* asciibuf = HBufC8::NewLC(KMaxDBFieldNameLength);
	TPtr8 asciiString = asciibuf->Des();
	asciiString.Copy(reinterpret_cast<const unsigned char *>(field));
			
	// Buffer for unicode parameter
	HBufC* unicodebuf = HBufC::NewLC(KMaxDBFieldNameLength);
	TPtr unicodeString = unicodebuf->Des();
	
	// Convert to unicode 
	unicodeString.Copy(asciiString);
	
	// Now do the database query
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	_LIT(KSQLQueryRow, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQueryRow,
		&unicodeString,
		&KAkaTableName, 
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
		eap_status_e status;
		view.GetL();
				
		switch (view.ColType(KDefaultColumnInView_One))
		{
		case EDbColText:
			{
				unicodeString = view.ColDes(KDefaultColumnInView_One);
				// Convert to 8-bit
				asciiString.Copy(unicodeString);
				if (asciiString.Size() > 0)
				{
					status = data->set_copy_of_buffer(asciiString.Ptr(), asciiString.Size());
					if (status != eap_status_ok)
					{
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}
				} 
				else 
				{
					status = data->init(0);
					if (status != eap_status_ok)
					{
						User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
					}
					data->set_is_valid();					
					break;
				}
			}
			break;

		case EDbColUint32:
			{
				TUint value;
				value = view.ColUint32(KDefaultColumnInView_One);
				status = data->set_copy_of_buffer(&value, sizeof(value));
				if (status != eap_status_ok)
				{
					User::Leave(m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status)));
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
	
	CleanupStack::PopAndDestroy(4); // Close view, & 3 strings

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::type_configure_write(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
{
	// NOTE: At the moment this is not called anywhere.
	// NOTE: This is really just for simulation.
	// Write is routed to partner object.
	eap_status_e status = m_partner->write_configure(
			field,
			data);
	return status;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_type_aka_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_type_aka_symbian_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

#if defined(__WINS__)

EAP_FUNC_EXPORT eap_status_e eap_am_type_aka_symbian_c::query_SIM_imsi(
	u8_t * const imsi, const u32_t max_length, u32_t * const imsi_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (imsi == 0 || imsi_length == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// This function returns Nokia test SIM IMSI.
	// It is used only when real AKA interface is not used.	
	
	*imsi_length = m_am_tools->strlen(TEST_IMSI);
	if (*imsi_length > max_length)
	{
		// ERROR, too short buffer.
		*imsi_length = 0u;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}
	m_am_tools->memmove(imsi, TEST_IMSI, m_am_tools->strlen(TEST_IMSI));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

#endif //#if defined(__WINS__)

//--------------------------------------------------

eap_status_e eap_am_type_aka_symbian_c::check_is_valid_imsi(
	const eap_variable_data_c * const username)
{
	if (username == 0
		|| username->get_is_valid_data() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	for (u32_t ind = 0ul; ind < username->get_data_length(); ind++)
	{
		const u8_t * const digit = username->get_data_offset(
			ind,
			sizeof(u8_t));
		if (digit == 0
			|| *digit < '0'
			|| *digit > '9')
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_identity);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_type_aka_symbian_c::is_session_valid()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	bool sessionValidity(false);
	
	TRAPD(err, sessionValidity = is_session_validL());
	if (err != KErrNone) 
	{
		EAP_TRACE_ERROR(m_am_tools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("eap_am_type_aka_symbian_c::is_session_valid - LEAVE - error=%d, Assuming session is invalid \n"),
			err));
			
		sessionValidity = false;
	}
	 		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	return sessionValidity;
}

//--------------------------------------------------

bool eap_am_type_aka_symbian_c::is_session_validL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_aka_symbian_c::is_session_valid - start \n")));

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S, %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&cf_str_EAP_AKA_max_session_validity_time_literal,
		&KAKALastFullAuthTime,
		&KAkaTableName,
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
		
	TInt64 maxSessionTime = view.ColInt64(colSet->ColNo(cf_str_EAP_AKA_max_session_validity_time_literal));
	TInt64 fullAuthTime = view.ColInt64(colSet->ColNo(KAKALastFullAuthTime));

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
		
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_aka_symbian_c::is_session_valid:interval in microseconds:"),
			&(interval.Int64()),
			sizeof(interval.Int64()) ) );
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("eap_am_type_aka_symbian_c::is_session_valid:max session time in microseconds:"),
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
			(EAPL("eap_am_type_aka_symbian_c::is_session_validL()")
			 EAPL("interval in Minutes =%d\n"),
			 intervalMins.Int()));
	}
	
#endif


	if( maxSessionTime >= interval.Int64() )
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_aka_symbian_c::is_session_valid - Session Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			

		return true;	
	}
	else
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_aka_symbian_c::is_session_valid - Session NOT Valid \n")));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
		
		return false;	
	}
}

//--------------------------------------------------

void eap_am_type_aka_symbian_c::store_authentication_timeL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_type_aka_symbian_c::store_authentication_timeL - start \n")));	

	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();
	
	// Query all the relevant parameters
	_LIT(KSQLQuery, "SELECT %S FROM %S WHERE %S=%d AND %S=%d AND %S=%d AND %S=%d");
	sqlStatement.Format(
		KSQLQuery,
		&KAKALastFullAuthTime,
		&KAkaTableName,
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
	(EAPL("eap_am_type_aka_symbian_c::store_authentication_time, %2d-%2d-%4d : %2d-%2d-%2d-%d\n"), 
	currentDateTime.Day()+1, currentDateTime.Month()+1,currentDateTime.Year(), currentDateTime.Hour(),
	currentDateTime.Minute(), currentDateTime.Second(), currentDateTime.MicroSecond()));

#endif

	TInt64 fullAuthTime = currentTime.Int64();
	
	view.SetColL(colSet->ColNo(KAKALastFullAuthTime), fullAuthTime);

	view.PutL();	

	CleanupStack::PopAndDestroy(colSet); // Delete colSet.
	CleanupStack::PopAndDestroy(&view); // Close view.
	CleanupStack::PopAndDestroy(buf); // Delete buf.

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);			
}

//--------------------------------------------------

//  End of File
