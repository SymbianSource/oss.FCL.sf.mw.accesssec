/*
* Copyright (c) 2005-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  CEapVpnInterfaceImplementation
*
*/

/*
* %version: 67 %
*/

// INCLUDE FILES
#include <w32std.h>
#include <pathinfo.h>

#include <EapType.h>
#include <EapTypePlugin.h>
#include <EapGeneralSettings.h>

#include "eap_vpn_if_implementation.h"
#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_type_all.h"
#include "eap_am_tools_symbian.h"
#include "eap_crypto_api.h"
#include "eap_type_gsmsim.h"
#include "eap_type_aka.h"
#include "eap_header_string.h"
//#include "EapolDbDefaults.h"
//#include "EapolDbParameterNames.h"
#include "eap_am_file_input_symbian.h"
#include "abs_eap_vpn_if.h"
#include "eap_array_algorithms.h"
#include "eap_core.h"

#include "EapSimDbDefaults.h"
#include "EapConversion.h"
#include "eap_session_core_base.h"
#include "eap_automatic_variable.h"
#include "eap_core_client_message_if.h"
#include "eap_process_tlv_message_data.h"
#include "eapol_wlan_database_reference.h"

// LOCAL CONSTANTS
const TUint KMaxConfigStringLength = 256;
const u32_t KMTU = 1500u;
const u32_t KTrailerLength = 0;
const u32_t KHeaderOffset = 0;

#define KEapIdentityOffset 5

#ifdef USE_EAP_VPN_FILETRACE
const eap_const_string EAPPLUGIN_TRACE_FILE = EAPL("logs\\eapol\\eap_vpn_if.txt");
#endif

enum eapol_am_core_timer_id_e
{
	EAPOL_AM_CORE_TIMER_RESTART_AUTHENTICATION_ID,
	EAPOL_AM_CORE_TIMER_DELETE_STACK_ID,
	EAPOL_AM_CORE_TIMER_FAILED_COMPLETELY_ID,
};

// ================= MEMBER FUNCTIONS =======================
// Create instance of concrete ECOM interface implementation
CEapVpnInterfaceImplementation* CEapVpnInterfaceImplementation::NewL(TAbsEapVpnInterfaceParams* aParams)
{
	CEapVpnInterfaceImplementation* self = new (ELeave) CEapVpnInterfaceImplementation;
	CleanupStack::PushL(self);
	self->ConstructL(aParams->iCaller, aParams->iClient);

	if (self->get_is_valid() != true)
	{
		User::Leave(KErrGeneral);
	}

	CleanupStack::Pop();
	return self;
}

	
//--------------------------------------------------
// Constructor
//--------------------------------------------------

/// VPN does not have any IAP setting at all but we use index 1 in the EAP databases
/// for all VPN related settings.
const TInt EAP_VPN_DEFAULT_SERVICE_TABLE_INDEX = 1; 

CEapVpnInterfaceImplementation::CEapVpnInterfaceImplementation()
: m_trace_log_file_name(0)
, m_is_client(true)
, m_eap_type_array(0)
, m_index_type(EVpn)
, m_index(EAP_VPN_DEFAULT_SERVICE_TABLE_INDEX)
{
}
	
//--------------------------------------------------
// Second phase construction.
//--------------------------------------------------
void CEapVpnInterfaceImplementation::ConstructL(MAbsEapVpnInterface* aCaller, TBool aClient)
{
    EAP_TRACE_DEBUG(
        m_am_tools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("CEapVpnInterfaceImplementation::ConstructL()\n")));

	iCaller = aCaller;
	if(aClient)
	{
		m_is_client = true;
	}
	else
	{
		m_is_client = false;
	}

	if (iCaller == 0)
	{
		User::Leave(KErrGeneral);
	}

	// Create tools class
	m_am_tools = new(ELeave) eap_am_tools_symbian_c(0);

	if (m_am_tools->get_is_valid() != true)
	{
		// The real reason most likely is KErrNoMemory but since that is not sure we'll use KErrGeneral
		User::Leave(KErrGeneral);
	}

	if (m_am_tools->configure() != eap_status_ok)
	{
		User::Leave(KErrGeneral);
	}


#ifdef USE_EAP_VPN_FILETRACE
	{
		TFileName drivePath( PathInfo::MemoryCardRootPath() );

		const TInt MAXPATHNAME=256ul;

		HBufC* buf = HBufC::NewLC(MAXPATHNAME);
		TPtr pathbuffer = buf->Des();

		pathbuffer.Append( TParsePtrC( drivePath ).DriveAndPath() );

		{
			eap_variable_data_c unicode_drivepath(m_am_tools);
			if (unicode_drivepath.get_is_valid() == false)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				User::Leave(KErrGeneral);
			}

			eap_status_e status = unicode_drivepath.set_buffer(pathbuffer.Ptr(), pathbuffer.Length(), false, false);
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				User::Leave(KErrGeneral);
			}

			eap_variable_data_c utf8_drivepath(m_am_tools);
			if (utf8_drivepath.get_is_valid() == false)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				User::Leave(KErrGeneral);
			}

			status = m_am_tools->convert_unicode_to_utf8(
				utf8_drivepath,
				unicode_drivepath);
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				User::Leave(KErrGeneral);
			}

			delete m_trace_log_file_name;
			m_trace_log_file_name = new eap_variable_data_c(m_am_tools);

			if (m_trace_log_file_name == 0
				|| m_trace_log_file_name->get_is_valid() == false)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
				User::Leave(KErrGeneral);
			}

			status = m_trace_log_file_name->set_copy_of_buffer(&utf8_drivepath);
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				User::Leave(KErrGeneral);
			}

			status = m_trace_log_file_name->add_data(EAPPLUGIN_TRACE_FILE, sizeof(EAPPLUGIN_TRACE_FILE)-1);
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				User::Leave(KErrGeneral);
			}

			status = m_trace_log_file_name->add_end_null();
			if (status != eap_status_ok)
			{
				(void) EAP_STATUS_RETURN(m_am_tools, status);
				User::Leave(KErrGeneral);
			}
		}

		CleanupStack::PopAndDestroy(buf); // Delete pathbuffer.
	}
#endif

	m_eap_type_array = new eap_array_c<eap_type_value_e>(m_am_tools);
	if (m_eap_type_array == 0)
	{
		User::Leave(KErrGeneral);
	}

    //------ Create network id
	{
		EAP_TRACE_DEBUG(
    		m_am_tools,
    		TRACE_FLAGS_DEFAULT,
    		(EAPL("CEapVpnInterfaceImplementation: Create network ID\n")));

		u32_t NWID_SRC = 0;
		u32_t NWID_DEST = 1;
		const u16_t EAP_DUMMY_PACKET_TYPE = 1;

		m_receive_network_id = new eap_am_network_id_c(
			m_am_tools);

		if (m_receive_network_id == NULL
			|| m_receive_network_id->get_is_valid() != true)
		{
			delete m_receive_network_id;
			m_receive_network_id = 0;
			User::Leave(KErrGeneral);
		}

		eap_status_e status = m_receive_network_id->set_copy_of_am_network_id(
			&NWID_SRC,
			sizeof(NWID_SRC),
			&NWID_DEST,
			sizeof(NWID_DEST),
			EAP_DUMMY_PACKET_TYPE);
		if (status != eap_status_ok)
		{
			delete m_receive_network_id;
			m_receive_network_id = 0;
			User::Leave(KErrGeneral);
		}
	}


    m_am_tools->set_trace_mask(
		eap_am_tools_c::eap_trace_mask_debug
		| eap_am_tools_c::eap_trace_mask_always
		| eap_am_tools_c::eap_trace_mask_functions
		| eap_am_tools_c::eap_trace_mask_error
		| eap_am_tools_c::eap_trace_mask_message_data);

    
#if !defined(USE_EAP_RDEBUG_TRACE)
	{
		eap_variable_data_c trace_output_file(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_output_file_name.get_field(),
			&trace_output_file);

		if (status == eap_status_ok
			&& trace_output_file.get_is_valid_data() == true)
		{
			(void) m_am_tools->set_trace_file_name(&trace_output_file);
		}
	}
#endif //#if defined(USE_EAP_RDEBUG_TRACE)

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation: configure\n")));

	if (configure() != eap_status_ok)
	{
		User::Leave(KErrGeneral);
	}

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Configured EAPPlugin...\n")));

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("==================\n")));

	set_is_valid();
}


//--------------------------------------------------
// Destructor    
//--------------------------------------------------

CEapVpnInterfaceImplementation::~CEapVpnInterfaceImplementation()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::~CEapVpnInterfaceImplementation() - destructor\n")));

#ifdef USE_EAP_VPN_FILETRACE
	delete m_trace_log_file_name;
	m_trace_log_file_name = 0;
#endif
	shutdown();
}


    
//--------------------------------------------------
// Shutdown()
//--------------------------------------------------
eap_status_e CEapVpnInterfaceImplementation::shutdown()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation: Shutdown called\n")));

	// Cancel timer	
	cancel_all_timers();

	// Delete upper stack if it still exists
	if (iEapCore != 0)
	{
		iEapCore->shutdown();
		delete iEapCore;
		iEapCore = NULL;
	}

	// Print some statistics
	if (m_is_client)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_TEST_VECTORS,
			(EAPL("client authentication SUCCESS %d, FAILED %d\n"),
			m_successful_authentications,
			m_failed_authentications));	
	}
	else
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_TEST_VECTORS,
			(EAPL("server authentication SUCCESS %d, FAILED %d\n"),
			m_successful_authentications,
			m_failed_authentications));
	}	

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("EAPPlugin EXITING.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	

	if(m_receive_network_id != 0)
	{
		delete m_receive_network_id;
	}

	{
		// Unload all loaded EAP-interfaces.
		for(int i = 0; i < m_eap_if_array.Count(); i++)
		{
			delete m_eap_if_array[i];
		}

		m_eap_if_array.Close();
	}

	{
		// Unload all loaded EAP-plugins.
		for(int i = 0; i < m_eap_plugin_if_array.Count(); i++)
		{
			delete m_eap_plugin_if_array[i];
		}

		m_eap_plugin_if_array.Close();
	}

	m_enabled_expanded_eap_array.ResetAndDestroy();

	m_disabled_expanded_eap_array.ResetAndDestroy();
	
	m_eap_type_array->reset();

	delete m_eap_type_array;
	m_eap_type_array = 0;

	delete iManualUsername;
	iManualUsername = NULL;

	delete iManualRealm;
	iManualRealm = NULL;

	delete iRealmPrefix;
	iRealmPrefix = NULL;

	// Finally delete tools. No logging is allowed after this.
	if (m_am_tools != 0)
	{
		m_am_tools->shutdown();
		delete m_am_tools;
	}

	return eap_status_ok;
}

//--------------------------------------------------

//
void CEapVpnInterfaceImplementation::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation: RunL(): iStatus.Int() = %d\n"),
		iStatus.Int()));

	if (iStatus.Int() != KErrNone)
	{
		return;
	}

	// Authentication cancelled.
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Authentication cancelled.\n")));

	// Set block on.
	m_block_packet_sends_and_notifications = true;

	// Reset flags
	m_stack_marked_to_be_deleted = true;
	set_timer(this, EAPOL_AM_CORE_TIMER_DELETE_STACK_ID, 0, 0);

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("Indication sent: EFailedCompletely.\n")));

	iCaller->EapIndication(EFailedCompletely);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

//--------------------------------------------------

//
void CEapVpnInterfaceImplementation::DoCancel()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_vpn_if::DoCancel()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}

    
//--------------------------------------------------
// Configure()        
//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::configure()
{	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::configure()\n")));

    //----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_trace_on_error(m_am_tools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_trace_on_error.get_field(),
			&EAP_TRACE_activate_trace_on_error);

		if (status == eap_status_ok
			&& EAP_TRACE_activate_trace_on_error.get_is_valid_data() == true)
		{
			u32_t *activate_trace_on_error = (u32_t *)EAP_TRACE_activate_trace_on_error.get_data(sizeof(u32_t));

			if (activate_trace_on_error != 0
				&& *activate_trace_on_error != 0)
			{
				m_am_tools->set_activate_trace_on_error();
			}
		}
	}

	//----------------------------------------------------------

	// All of the configuration options are optional.
	// So we return OK.
	return eap_status_ok;
}
    
//----------------------------------------------------------        
// Implementations of virtual functions from CEapVpnInterface
//----------------------------------------------------------

/**
 * Function:    EapConfigure
 *
 * Description: Configures the eap plugin
 *
 * @param       aManualUsername The username, if not zero
 * @param       aManualRealm The realm, if not zero
 * @param       aManualRealmPrefix The realm prefix, if not zero
 * @param       aHideInitialIdentity Scramble username, if true
 *
 */
TInt CEapVpnInterfaceImplementation::EapConfigure(
	TDesC8& aManualUsername,
	TDesC8& aManualRealm,
	TDesC8& aRealmPrefix,
	TBool aHideInitialIdentity)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure()\n")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): aManualUsername\n"),
		aManualUsername.Ptr(),
		aManualUsername.Size()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): aManualRealm\n"),
		aManualRealm.Ptr(),
		aManualRealm.Size()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): aRealmPrefix\n"),
		aRealmPrefix.Ptr(),
		aRealmPrefix.Size()));

	iHideInitialIdentity = aHideInitialIdentity;

	delete iManualUsername;
	iManualUsername = NULL;

	delete iManualRealm;
	iManualRealm = NULL;

	delete iRealmPrefix;
	iRealmPrefix = NULL;

	TRAPD(error,
		iManualUsername = aManualUsername.AllocL();
		iManualRealm = aManualRealm.AllocL();
		iRealmPrefix = aRealmPrefix.AllocL();
		);

	if (error != KErrNone)
	{
		EAP_TRACE_ERROR(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): error = %d\n"),
			error));
		return error;
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): iManualUsername\n"),
		iManualUsername->Ptr(),
		iManualUsername->Size()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): iManualRealm\n"),
		iManualRealm->Ptr(),
		iManualRealm->Size()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): iRealmPrefix\n"),
		iRealmPrefix->Ptr(),
		iRealmPrefix->Size()));

		//--------------------------------------------------------
		//--------------------------------------------------------
		// Set the values for realm and user name if there is any.
		// If there is no values the default settings will be used( automatic realm and username).


	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): About to configure manual/auto username and manual/auto realm, m_index_type=%d, m_index=%d\n"),
			m_index_type,
			m_index));

		CEapType* eapType = 0;

		// Check if this EAP type has already been loaded
		i32_t eapArrayIndex = find<eap_type_value_e>(
			m_eap_type_array,
			&iRequestedEapType,
			m_am_tools);

		if (eapArrayIndex >= 0)
		{
			// Yep. It was loaded already.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): EAP Type Already loaded\n")));

			eapType = m_eap_if_array[eapArrayIndex];		
		}
		else 
		{
			// We must have a trap here since the EAP core knows nothing about Symbian.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): EAP Type new\n")));

			TEapExpandedType aEapType;

			TInt error = CEapConversion::ConvertInternalTypeToExpandedEAPType(
				&iRequestedEapType,
				&aEapType);
			if (error != KErrNone)
			{
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("ERROR: CEapVpnInterfaceImplementation::EapConfigure(): Error from CEapConversion::ConvertExpandedEAPTypeToInternalType()=%d\n"),
					error));		
			
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
			}

			TRAP(error, (eapType = CEapType::NewL(m_index_type, m_index, aEapType)));	

			if (error != KErrNone
				|| eapType == 0)
			{
				// Interface not found or implementation creation function failed
				
				delete eapType;
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): EAP Type new, unable to load\n")));
				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ECom could not find/initiate implementation.\n")));
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Add EAP-interface information to the member arrays.
			if (m_eap_if_array.Append(eapType) != KErrNone)
			{
				delete eapType;
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);				
			}
		}
		
		EAPSettings* setSettings = new EAPSettings;
		if( setSettings == NULL )     
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): EAPSettings allocation error \n")));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);				
		}
		
		if(iRequestedEapType == eap_type_aka)
		{
			setSettings->iEAPExpandedType = *EapExpandedTypeAka.GetType();
			
		}
		else if(iRequestedEapType == eap_type_gsmsim)
		{
			setSettings->iEAPExpandedType = *EapExpandedTypeSim.GetType();
		}
		else
		{
			delete setSettings;

			// Only EAP-SIM and AKA are possible now.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
		}
		
		if(iManualUsername && iManualUsername->Length() != 0)
		{
    		setSettings->iUsernamePresent = ETrue; // Same value for both SIM and AKA.
	    	setSettings->iUsername.Copy(iManualUsername->Des());
		}
		else
		{
	    	// No user name. we have to set automatic now.
	    	setSettings->iUsernamePresent = EFalse; // Same value for both SIM and AKA.
	    	setSettings->iUseAutomaticUsernamePresent = ETrue; // Same value for both SIM and AKA.
	    	setSettings->iUseAutomaticUsername = ETrue; // Same value for both SIM and AKA.
		}
		
		if(iManualRealm && iManualRealm->Length() != 0)
		{
	    	setSettings->iRealmPresent = ETrue; // Same value for both SIM and AKA.
	    	setSettings->iRealm.Copy(iManualRealm->Des());
		}
		else
		{
	    	// No realm. we have to set automatic now.
	    	setSettings->iRealmPresent = EFalse; // Same value for both SIM and AKA.
	    	setSettings->iUseAutomaticRealmPresent = ETrue; // Same value for both SIM and AKA.
	    	setSettings->iUseAutomaticRealm = ETrue; // Same value for both SIM and AKA.
		}    
		
		TRAP(error, eapType->SetConfigurationL(*setSettings) );

		delete setSettings;
		setSettings = 0;

		if ( error != KErrNone )
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapVpnInterfaceImplementation::EapConfigure(): Setting Manual Username and Realm failed. SetConfigurationL() error=%d\n")));
			return error;
		}
	}

	{
		CEapGeneralSettings* genSet = NULL;

		TRAPD(error, genSet = CEapGeneralSettings::NewL(m_index_type, m_index));

		if (error != KErrNone)
		{
			delete genSet;

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapVpnInterfaceImplementation::EapConfigure(): CEapGeneralSettings::NewL() error=%d\n")));
			return error;
		}

		TEapExpandedType tmpEap;
		RArray<TEapExpandedType> OuterEapsOn;
	    RArray<TEapExpandedType> OuterEapsOff;

		tmpEap.SetValue(
			iRequestedEapType.get_vendor_id(),
			iRequestedEapType.get_vendor_type());

		error = OuterEapsOn.Append(tmpEap);
		if(error != KErrNone)
		{
			OuterEapsOn.Close();
			OuterEapsOff.Close();
			delete genSet;

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapVpnInterfaceImplementation::EapConfigure(): OuterEapsOn.Append() error=%d\n")));
			return error;
		}

		error = genSet->SetEapMethods(OuterEapsOn, OuterEapsOff);

		OuterEapsOn.Close();
		OuterEapsOff.Close();
		delete genSet;

		if (error != KErrNone)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CEapVpnInterfaceImplementation::EapConfigure(): SetEapMethods() error=%d\n")));
			return error;
		}

	}

	{
		eap_status_e status(eap_status_ok);

		eap_variable_data_c reference(m_am_tools);

		{
			eapol_wlan_database_reference_values_s values = {m_index_type, m_index};

			status = reference.set_copy_of_buffer(&values, sizeof(values));
			if (status != eap_status_ok)
			{
				return m_am_tools->convert_eapol_error_to_am_error(
					EAP_STATUS_RETURN(m_am_tools, status));
			}
		}

		status = iEapCore->set_eap_database_reference_values(&reference);
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		eap_variable_data_c SSID(m_am_tools);

		if (SSID.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): SSID failed.\n")));
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
		}

		const u8_t dummy[] = "dummy";
		status = SSID.set_copy_of_buffer(dummy, sizeof(dummy));
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		eap_variable_data_c preshared_key(m_am_tools);
		if (preshared_key.get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("CEapVpnInterfaceImplementation::EapConfigure(): preshared_key failed.\n")));
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
		}

		// This is asynchronous function call that is completed by complete_get_802_11_authentication_mode() function call.
		status = iEapCore->get_802_11_authentication_mode(
			m_receive_network_id,
			eapol_key_authentication_type_RSNA_EAP,
			&SSID,
			&preshared_key);
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		status = wait_complete_get_802_11_authentication_mode();
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status));
		}

		// Creates a EAP-session.
		status = iEapCore->create_eap_session(m_receive_network_id);
		if (status != eap_status_ok)
		{
			return m_am_tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(m_am_tools, status));
		}
	}
    
	return KErrNone;
}

//--------------------------------------------------

/**
 * Function:    StartL
 *
 * Description: Initializes the eap plugin
 *
 */
TInt CEapVpnInterfaceImplementation::StartL(const TUint8 aEapType)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::StartL()\n")));

	eap_status_e status(eap_status_ok);
	iQueryIdentity = EFalse;

	iRequestedEapType = static_cast<eap_type_ietf_values_e>(aEapType);

	if (iEapCore != 0)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Deleting previously used stack.\n")));

		// It is an error to call start without calling disassociated
		if (m_stack_marked_to_be_deleted == false)
		{	
			EAP_TRACE_ERROR(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_vpn_if::Start called twice!\n")));
			return KErrAlreadyExists;
		}

		// The previously used stack is perhaps still waiting for deletion.
		cancel_timer(this, EAPOL_AM_CORE_TIMER_DELETE_STACK_ID);

		// Delete stack
		iEapCore->shutdown();
		delete iEapCore;
		iEapCore = 0;				

		m_stack_marked_to_be_deleted = false;
	}

	// Clear packet send and notification blocking.
	m_block_packet_sends_and_notifications = false;

	if (m_enabled_expanded_eap_array.Count() == 0)
	{
		// The EAP field was empty. Allow all types.

		EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Empty EAP field -> enable all types.\n")));

		RImplInfoPtrArray eapArray;
		CleanupStack::PushL( TCleanupItem( CleanupImplArray, &eapArray ) );

		REComSession::ListImplementationsL(KEapTypeInterfaceUid, eapArray);

		for (TInt i = 0; i < eapArray.Count(); i++)
		{
			SEapExpandedType * expandedEAPType = new (ELeave) SEapExpandedType;
			expandedEAPType->EapExpandedType = eapArray[i]->DataType();
					
			eap_expanded_type_c tmpExpEAPType;
			
			// This is to make the tmpExpEAPType in 8 byte string with correct vendor type and vendor id details.
			status = eap_expanded_type_c::read_type(m_am_tools,
													0, // index should be zero here.
													expandedEAPType->EapExpandedType.Ptr(),
													KExpandedEapTypeSize,
													&tmpExpEAPType);
			if (status != eap_status_ok)
			{
				delete expandedEAPType;
				expandedEAPType = 0;

				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::StartL: eap_expanded_type_c::write_type failed \n")));
			
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			// Now add the EAP types to the array
			if(tmpExpEAPType == iRequestedEapType)
			{
				// This is the requested EAP type.
				
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::StartL:Enabled (Requested) EAP type:"),
					expandedEAPType->EapExpandedType.Ptr(),
					expandedEAPType->EapExpandedType.Size()));
			
				m_enabled_expanded_eap_array.Insert(expandedEAPType, 0); // This goes to the beginning.
			}
			else
			{
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::StartL:Disabled EAP type:"),
					expandedEAPType->EapExpandedType.Ptr(),
					expandedEAPType->EapExpandedType.Size()));

				delete expandedEAPType;
				expandedEAPType = 0;

			}
		} // for()

		CleanupStack::PopAndDestroy(&eapArray);
	}

	CompleteAssociation(status);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

//
TInt CEapVpnInterfaceImplementation::CompleteAssociation(
		const TInt aResult
		)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::CompleteAssociation(): aResult=%d\n"),
		aResult));

	eap_status_e status(eap_status_ok);

	// ASSOCIATION UNSUCCESSFUL
	if (aResult != KErrNone)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CompleteAssociation: Unsuccessful.\n")));
			iCaller->EapIndication(EFailedCompletely);
		return KErrNone;
	}

	// ASSOCIATION SUCCESSFUL
	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
		(EAPL("CompleteAssociation: Successful.\n")));

	// Create stack if it does not already exist. 
	status = create_upper_stack();

	if (status != eap_status_ok
		&& status != eap_status_already_exists)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
			(EAPL("Indication sent to VPN: EFailedCompletely.\n")));

		iCaller->EapIndication(EFailedCompletely);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
		return KErrNone; 
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

/**
 * Function:    QueryIdentity
 *
 * Description: Ask the identity
 *
 * @param       aType name of requested eap type implementation.
 */
TInt CEapVpnInterfaceImplementation::QueryIdentity()
{
	// Build Eap Identity reques message
	// and send it to eap_core.
	// Eap core determines the identity and
	// responses with packet_send() callback
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::QueryIdentity()\n")));

	// Build identity request only if GSM/SIM or AKA
	if((iRequestedEapType != eap_type_gsmsim) && (iRequestedEapType != eap_type_aka))
	{
		TRAPD(error, (iCaller->EapIdentityResponseL(NULL)));
		if(error != KErrNone)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));				
		}
		return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, eap_status_ok));
	}

	iQueryIdentity = ETrue;
	eap_status_e status(eap_status_ok);

	status = send_eap_identity_request();

	if(status == eap_status_pending_request)
	{
		// Request pending, it's OK
		status = eap_status_ok;
	}

	if(status != eap_status_ok)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_vpn_if::QueryIdentity() error, status = %d\n"), status));

		iQueryIdentity = EFalse;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------

//
eap_status_e CEapVpnInterfaceImplementation::send_eap_identity_request()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	eap_status_e status = eap_status_process_general_error;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::send_eap_identity_request()\n")));

	// Creates a identity request message.
	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		EAP_CORE_PACKET_BUFFER_LENGTH);

	if (request_packet.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_eap_identity_request(): %s, %s, packet buffer corrupted.\n"),
			(m_is_client == true) ? "client": "server"
			));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t buffer_size = EAP_CORE_PACKET_BUFFER_LENGTH;

	eap_header_wr_c eap_request(
		m_am_tools,
		request_packet.get_data_offset(0, buffer_size),
		buffer_size);

	if (eap_request.get_is_valid() == false)
	{
		EAP_TRACE_ERROR(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("send_eap_identity_request():packet buffer corrupted.\n")
			));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_header_corrupted);
	}

	eap_request.set_length((u16_t)(EAP_CORE_PACKET_BUFFER_LENGTH), true);
	eap_request.set_code(eap_code_request);
	eap_request.set_identifier(0);
	eap_request.set_type_data_length(0u, false);
	eap_request.set_type(eap_type_identity, false);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapVpnInterfaceImplementation::send_eap_identity_request(): %s, code=0x%02x=%s, identifier=0x%02x, length=0x%04x, type=0x%08x=%s, packet length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eap_request.get_code(),
		eap_request.get_code_string(),
		eap_request.get_identifier(),
		eap_request.get_length(),
		convert_eap_type_to_u32_t(eap_request.get_type()),
		eap_request.get_type_string(),
		eap_request.get_length()));

	EAP_ASSERT(eap_request.get_length() >= 4);

	status = iEapCore->packet_process(
		m_receive_network_id,
		&eap_request,
		eap_request.get_length());

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::send_identity_request(): iEapCore->packet_process() = %d\n"), status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * Function:    EapInbound
 *
 * Description: Handle incoming eap message.
 *
 * @param       aMessage incoming eap message.
 *              
 */
TInt CEapVpnInterfaceImplementation::EapInbound(const TDesC8& aMessage)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);	

	// from eapol_am_core_symbian.cpp ReceivePacket
	iQueryIdentity = EFalse;
	eap_status_e status(eap_status_ok);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapInbound()\n")));

	TInt length = aMessage.Length();
	if (length < 4)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return m_am_tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(m_am_tools, eap_status_too_short_message));
	}

	// Creates a identity request message.
	eap_buf_chain_wr_c request_packet(
		eap_write_buffer, 
		m_am_tools, 
		aMessage.Length());

	request_packet.add_data(aMessage.Ptr(), aMessage.Length());

	eap_header_wr_c eap_request(
		m_am_tools,
		request_packet.get_data_offset(0, aMessage.Length()),
		aMessage.Length());

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapVpnInterfaceImplementation::EapInbound(): %s, code=0x%02x=%s, identifier=0x%02x, length=0x%04x, type=0x%08x=%s, packet length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eap_request.get_code(),
		eap_request.get_code_string(),
		eap_request.get_identifier(),
		eap_request.get_length(),
		convert_eap_type_to_u32_t(eap_request.get_type()),
		eap_request.get_type_string(),
		eap_request.get_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::EapInbound(): EAP-packet"),
		aMessage.Ptr(),
		aMessage.Length()));

	// Forward the packet to the Eap layer of the EAPOL stack. Ignore return value. Failure is signalled using state_notification.
	status = iEapCore->packet_process(
		m_receive_network_id,
		&eap_request,
		length);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::iEapCore->packet_process() = %d\n"), status));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return m_am_tools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(m_am_tools, status));
}

//--------------------------------------------------
// create_upper_stack
//--------------------------------------------------
eap_status_e CEapVpnInterfaceImplementation::create_upper_stack()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::create_upper_stack()\n")));

	eap_status_e status(eap_status_ok);

	if (iEapCore == 0)
	{        
		iEapCore = new_eap_core_client_message_if_c(
			m_am_tools,
			this,
			true,
			KMTU);

		if (iEapCore == 0
			|| iEapCore->get_is_valid() != true)
		{
			if (iEapCore != 0)
			{
				iEapCore->shutdown();
				delete iEapCore;
				iEapCore = 0;							
			}			
			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Stack creation failed.\n")));			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
		}

		// Initialise upper stack
		status = iEapCore->configure();

		if (status != eap_status_ok)
		{
			iEapCore->shutdown();
			delete iEapCore;
			iEapCore = 0;							

			EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Stack creation failed.\n")));			
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);	
		}
	}
	else
	{			
		status = eap_status_already_exists;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;	
}

//--------------------------------------------------

// Virtual callback function implementations, called by the eap_core

/**
 * The derived class could send packets to partner class with this function.
 * @see abs_eap_base_type_c::packet_send().
 */
eap_status_e CEapVpnInterfaceImplementation::packet_send(
	const eap_am_network_id_c * const /*send_network_id*/,
	eap_buf_chain_wr_c * const sent_packet,
	const u32_t header_offset,
	const u32_t data_length,
	const u32_t /*buffer_length*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::packet_send(data_length=%d)\n"),
		data_length));

	if (header_offset != 0u)
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet buffer corrupted.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}
	else if (header_offset+data_length != sent_packet->get_data_length())
	{
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: packet_send: packet buffer corrupted (data_length != sent_packet->get_data_length()).\n")));
			EAP_ASSERT(data_length == sent_packet->get_buffer_length());
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}	

	if (m_block_packet_sends_and_notifications == true)
	{
		// Packet sending block is active. This happens when disassociated has been called.  
		// start_authentication clears the block.
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("packet_send: packet ignored because Disassociated() was called.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	eap_header_wr_c eap(
		m_am_tools,
		sent_packet->get_data_offset(
			header_offset, data_length),
			data_length);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CEapVpnInterfaceImplementation::packet_send(): %s, code=0x%02x=%s, identifier=0x%02x, length=0x%04x, type=0x%08x=%s, packet length 0x%04x\n"),
		(m_is_client == true) ? "client": "server",
		eap.get_code(),
		eap.get_code_string(),
		eap.get_identifier(),
		eap.get_length(),
		convert_eap_type_to_u32_t(eap.get_type()),
		eap.get_type_string(),
		eap.get_length()));

	TInt status(KErrNone);
	if (status == KErrNone)
	{
		u8_t * const packet_data = sent_packet->get_data_offset(header_offset, data_length);
		if (packet_data == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_buffer_too_short;
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CEapVpnInterfaceImplementation::packet_send(): EAP-packet"),
			packet_data,
			data_length));

		// Here we send the original packet.
		HBufC8* eapData = NULL;
		TInt error = KErrNone;

		if(iQueryIdentity)
		{
			TPtr8 eapPtr(packet_data + KEapIdentityOffset, data_length - KEapIdentityOffset, data_length - KEapIdentityOffset);
			TRAP(error, eapData = eapPtr.Alloc());
		}
		else
		{
			TPtr8 eapPtr(packet_data, data_length, data_length);
			TRAP(error, eapData = eapPtr.Alloc());
		}

		if(error != KErrNone)
		{
			EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Allocation error\n")));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		if(iQueryIdentity)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation::EapIdentityResponseL()\n")));

			TRAPD(error, (iCaller->EapIdentityResponseL(eapData)));
			if(error != KErrNone)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));				
			}

			iQueryIdentity = EFalse;
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation::EapOutboundL()\n")));

			TRAPD(error, (iCaller->EapOutboundL(eapData)));
			if(error != KErrNone)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));				
			}
		}
		++m_packet_index;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(status));
}

//--------------------------------------------------

/**
 * The get_header_offset() function obtains the header offset of EAP-packet.
 * @see abs_eap_base_type_c::get_header_offset().
 */
u32_t CEapVpnInterfaceImplementation::get_header_offset(
	u32_t * const MTU,
	u32_t * const trailer_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	*MTU = KMTU;
	*trailer_length = KTrailerLength;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return KHeaderOffset;
}

//--------------------------------------------------

/**
 * The load_module() function function indicates the lower level to
 * load new module of EAP-type.
 * @param type is the requested EAP-type.
 * @param partner is pointer to the caller object.
 * The partner of the new created EAP-type object is the caller object.
 * @param eap_type is a pointer to a pointer of EAP-type object.
 * Adaptation module sets eap_type pointer to created EAP-type object.
 * @param is_client_when_true parameter indicates whether the network entity should
 * act as a client (true) or server (false), in terms of EAP-protocol whether
 * this network entity is EAP-supplicant (true) or EAP-authenticator (false).
 * @param receive_network_id includes the addresses (network identity) and packet type.
 */
eap_status_e CEapVpnInterfaceImplementation::load_module(
	const eap_type_value_e type,
	const eap_type_value_e tunneling_type,
	abs_eap_base_type_c * const partner,
	eap_base_type_c ** const eap_type_if,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::load_module()\n")));

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_vpn_if::load_module(type %d=%s, tunneling_type %d=%s)\n"),
		convert_eap_type_to_u32_t(type),
		eap_header_string_c::get_eap_type_string(type),
		convert_eap_type_to_u32_t(tunneling_type),
		eap_header_string_c::get_eap_type_string(tunneling_type)));

	EAP_UNREFERENCED_PARAMETER(type);
	EAP_UNREFERENCED_PARAMETER(tunneling_type);

	eap_status_e status = eap_status_process_general_error;

	if (type != iRequestedEapType)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("load_module: eap_expanded_type_c::write_type(): not supported EAP-method\n")));
	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
	}

	EAP_ASSERT_TOOLS(m_am_tools, (type == iRequestedEapType));

	TEapExpandedType aEapType;

	TInt error = CEapConversion::ConvertInternalTypeToExpandedEAPType(
		&iRequestedEapType,
		&aEapType);
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("ERROR: CEapVpnInterfaceImplementation::load_module(): Error from CEapConversion::ConvertExpandedEAPTypeToInternalType()=%d\n"),
			error));		
	
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));
	}

	i32_t eapArrayIndex = -1;

	{
		CEapType* eapType = 0;

		// Check if this EAP type has already been loaded
		eapArrayIndex = find<eap_type_value_e>(
			m_eap_type_array,
			&iRequestedEapType,
			m_am_tools);

		if (eapArrayIndex >= 0)
		{
			// Yep. It was loaded already.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: EAP Type Already loaded\n")));

			eapType = m_eap_if_array[eapArrayIndex];		
		}
		else 
		{
			// We must have a trap here since the EAP core knows nothing about Symbian.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: EAP Type new\n")));

			TRAP(error, (eapType = CEapType::NewL(m_index_type, m_index, aEapType)));	

			if (error != KErrNone
				|| eapType == 0)
			{
				// Interface not found or implementation creation function failed
				
				delete eapType;
				eapType = 0;
				
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation: EAP Type new, unable to load\n")));
				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ECom could not find/initiate implementation.\n")));
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Add EAP-interface information to the member arrays.
			if (m_eap_if_array.Append(eapType) != KErrNone)
			{
				delete eapType;
				status = eap_status_allocation_error;
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);				
			}
		}

#if 0

		//--------------------------------------------------------
		//--------------------------------------------------------
		// Set the values for realm and user name if there is any.
		// If there is no values the default settings will be used( automatic realm and username).

		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation::load_module - About to configure manual/auto username and manual/auto realm \n")));
		
			EAPSettings* setSettings = new EAPSettings;
			if( setSettings == NULL )     
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::load_module - EAPSettings allocation error \n")));
	    		
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);				
			}
			
			if(iRequestedEapType == eap_type_aka)
			{
				setSettings->iEAPExpandedType = *EapExpandedTypeAka.GetType();
				
			}
			else if(iRequestedEapType == eap_type_gsmsim)
			{
				setSettings->iEAPExpandedType = *EapExpandedTypeSim.GetType();
			}
			else
			{
				delete setSettings;
				setSettings = 0;

				// Only EAP-SIM and AKA are possible now.
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_eap_type);
			}
			
			if(iManualUsername && iManualUsername->Length() != 0)
			{
    			setSettings->iUsernamePresent = ETrue; // Same value for both SIM and AKA.
	    		setSettings->iUsername.Copy(iManualUsername->Des());
			}
			else
			{
	    		// No user name. we have to set automatic now.
	    		setSettings->iUsernamePresent = EFalse; // Same value for both SIM and AKA.
	    		setSettings->iUseAutomaticUsernamePresent = ETrue; // Same value for both SIM and AKA.
	    		setSettings->iUseAutomaticUsername = ETrue; // Same value for both SIM and AKA.
			}
			
			if(iManualRealm && iManualRealm->Length() != 0)
			{
	    		setSettings->iRealmPresent = ETrue; // Same value for both SIM and AKA.
	    		setSettings->iRealm.Copy(iManualRealm->Des());
			}
			else
			{
	    		// No realm. we have to set automatic now.
	    		setSettings->iRealmPresent = EFalse; // Same value for both SIM and AKA.
	    		setSettings->iUseAutomaticRealmPresent = ETrue; // Same value for both SIM and AKA.
	    		setSettings->iUseAutomaticRealm = ETrue; // Same value for both SIM and AKA.
			}    
			
			TRAP(error, eapType->SetConfigurationL(*setSettings) );
			if ( error != KErrNone )
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::load_module - Setting Manual Username and Realm failed.error=%d, Continuing \n")));
			}
			
			delete setSettings;
			setSettings = 0;    
		}
#endif

	}
    
	//--------------------------------------------------------
	//--------------------------------------------------------

	// Create the EAP protocol interface implementation.
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation: EAP Type new, GetStackInterfaceL()\n")));


	{
		CEapTypePlugin* eapPlugin = 0;

		TRAP(error, (eapPlugin = CEapTypePlugin::NewL(aEapType.GetValue(), m_index_type, m_index, m_am_tools)));

		if (error != KErrNone
			|| eapPlugin == 0)
		{
			// Interface not found or implementation creation function failed
			
			delete eapPlugin;
			eapPlugin = 0;
			
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: EAP Type new, unable to load\n")));
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ECom could not find/initiate implementation.\n")));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

#ifdef USE_EAP_SIMPLE_CONFIG

		TRAP(error, (*eap_type_if = eapPlugin->GetStackInterfaceL(
			m_am_tools, 
			partner, 
			is_client_when_true, 
			receive_network_id,
			0))); // Check this up.

#else

		TRAP(error, (*eap_type_if = eapPlugin->GetStackInterfaceL(
			m_am_tools, 
			partner, 
			is_client_when_true, 
			receive_network_id)));

#endif // #ifdef USE_EAP_SIMPLE_CONFIG

		if (error != KErrNone 
			|| *eap_type_if == 0 
			|| (*eap_type_if)->get_is_valid() == false)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: EAP Type new, GetStackInterfaceL(), failed = %d\n"), error));

			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Could not create EAP type interface instance. Error: %d\n"), error));

			status = eap_status_allocation_error;

			// Unload DLL (two ways, depending whether this type was already loaded...)
			if  (eapArrayIndex < 0)
			{
				// No need to call shutdown here because GetStackInterfaceL has done it.
				delete m_eap_if_array[m_eap_if_array.Count() - 1];
				m_eap_if_array.Remove(m_eap_if_array.Count() - 1);

				delete eapPlugin;
			}
			else
			{
				unload_module((eap_type_value_e)iRequestedEapType);
			}
			// Note: even in error cases eap_core_c deletes eap_type_if
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: EAP Type new, GetStackInterfaceL(), success\n")));

			status = eap_status_ok;

			if (eapArrayIndex  < 0)
			{
				// Add plugin information to the member arrays. There is no need to store eap_type pointer because
				// the stack takes care of its deletion.
				if (m_eap_plugin_if_array.Append(eapPlugin) != KErrNone)
				{
					delete m_eap_if_array[m_eap_if_array.Count() - 1];
					m_eap_if_array.Remove(m_eap_if_array.Count() - 1);

					delete eapPlugin;
					status = eap_status_allocation_error;
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);				
				}

				eap_type_value_e * tmpEAPType = new eap_type_value_e();
				if(tmpEAPType == NULL)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("eapol_am_wlan_authentication_symbian_c::load_module() eap_type_value_e creation failed\n")));
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);				
				}
				
				*tmpEAPType = type;
				
				status = m_eap_type_array->add_object(tmpEAPType, true);
				
				if (status != eap_status_ok)			
				{
					delete m_eap_if_array[m_eap_if_array.Count() - 1];
					m_eap_if_array.Remove(m_eap_if_array.Count() - 1);

					// Remove the eap type added just previously
					m_eap_plugin_if_array.Remove(m_eap_plugin_if_array.Count() - 1);
					delete eapPlugin;

					status = eap_status_allocation_error;

					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);				
				}
			} 
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * The unload_module() function unloads the module of a EAP-type. 
 * @param eap_type is the requested EAP-type.
 */
eap_status_e CEapVpnInterfaceImplementation::unload_module(const eap_type_value_e type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status(eap_status_type_does_not_exists_error);

	// Check if this EAP type has already been loaded
	TInt index = find<eap_type_value_e>(
		m_eap_type_array,
		&type,
		m_am_tools);
		
	if (index >= 0)
	{
		// EAP was loaded before.
		
		delete m_eap_if_array[index];
		m_eap_if_array.Remove(index);
		
		delete m_eap_plugin_if_array[index];
		m_eap_plugin_if_array.Remove(index);
		
		status = m_eap_type_array->remove_object(index);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}
//--------------------------------------------------

void CEapVpnInterfaceImplementation::set_is_valid()
{
	m_is_valid = true;
}

//--------------------------------------------------

bool CEapVpnInterfaceImplementation::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

void CEapVpnInterfaceImplementation::increment_authentication_counter()
{
	++m_authentication_counter;
}

//--------------------------------------------------

u32_t CEapVpnInterfaceImplementation::get_authentication_counter()
{
	return m_authentication_counter;
}

//--------------------------------------------------

bool CEapVpnInterfaceImplementation::get_is_client()
{
	return m_is_client;
}

//--------------------------------------------------

/**
 * Note this function is just an example. Parameters will change later.
 * The packet_data_crypto_keys() function gives the generated keys to lower level.
 * After EAP-authentication has generated the keys it calls this function
 * to offer the keys to lower level.
 * @see abs_eap_base_type_c::packet_data_crypto_keys().
 */
eap_status_e CEapVpnInterfaceImplementation::packet_data_crypto_keys(
    const eap_am_network_id_c * const /*send_network_id*/,
    const eap_master_session_key_c * const master_session_key
    )
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	HBufC8* sharedKey = NULL;
	TPtr8 keyPtr(
		master_session_key->get_data(
			master_session_key->get_data_length()/2),
		master_session_key->get_data_length()/2,
		master_session_key->get_data_length()/2);

	TRAPD(error, (sharedKey = keyPtr.AllocL()));
	if(error != KErrNone)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);				
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation: EapSharedKeyL()\n")));

	TRAP(error, (iCaller->EapSharedKeyL(sharedKey)));
	if(error != KErrNone)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(error));				
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

/**
 * The packet_data_session_key() function passes one traffic encryption key to 
 * the lower layers. Ultimately the key can end up to the WLAN hardware.
 * @param send_network_id carries the addresses (network identity) and type of the packet.
 * @param key is the encryption key
 * @param key_length is the length of the key
 * @param key_type describes the type of the key (WEP or something else...)
 * @param key_index is the index of the encryption key (there can be four broadcast keys in WEP for example)
 */
eap_status_e CEapVpnInterfaceImplementation::packet_data_session_key(
    const eap_am_network_id_c * const /*send_network_id*/,
    const eapol_session_key_c * const /*key*/
    )
{
	// Not used, but might be called?
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	TInt status(KErrNone);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(status));
}

//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::add_configuration_data(
	eap_process_tlv_message_data_c * const message,
	const eap_configuration_field_c * field,
	const eap_configure_type_e type,
	const eap_variable_data_c * const value_data
    )
{
	eap_variable_data_c selector(m_am_tools);

	eap_status_e status = selector.set_buffer(
		field->get_field(),
		field->get_field_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return status;
	}

	eap_config_value_c config(m_am_tools);

	if (config.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	config.set_type(type);

	status = config.get_data()->set_copy_of_buffer(
		value_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = message->add_parameter_data(
		&selector,
		&config);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

const TUint32 K2DigitMncMccList[]
	= {
		202,204,206,208,213,214,216,218,
		219,220,222,226,228,230,231,232,
		234,238,240,242,244,246,247,248,
		250,255,257,259,260,262,266,268,
		270,272,274,276,278,280,282,284,
		286,288,290,293,294,295,308,340,
		362,363,400,401,402,404,410,413,
		414,415,416,417,419,420,421,422,
		424,425,426,427,428,429,432,434,
		436,437,438,440,441,452,454,455,
		456,457,460,470,472,502,505,510,
		515,520,525,528,530,537,539,541,
		546,547,549,602,603,604,605,607,
		608,609,610,611,612,613,614,615,
		616,617,619,620,621,622,623,624,
		625,626,628,629,630,631,633,634,
		635,636,638,639,640,641,642,643,
		645,646,647,648,649,650,651,652,
		653,654,655,702,704,706,710,712,
		714,716,724,730,734,744,746,901
	};

//--------------------------------------------------

/**
 * The read_configure() function reads the configuration data identified
 * by the field string of field_length bytes length. Adaptation module must direct
 * the query to some persistent store.
 * @see abs_eap_base_type_c::read_configure().
 */
eap_status_e CEapVpnInterfaceImplementation::read_configure(
    const eap_configuration_field_c * const field,
    eap_variable_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_ASSERT_ALWAYS(data != NULL);
	EAP_ASSERT_ALWAYS(field->get_field_length() <= KMaxConfigStringLength);

	EAP_UNREFERENCED_PARAMETER(KMaxConfigStringLength);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::read_configure()\n")));

	eap_status_e status(eap_status_ok);

	m_am_tools->trace_configuration(
		status,
		field,
		data);


	// Check if the wanted parameter is default type

	if (field->get_type() == eap_configure_type_all_configurations
		&& field->compare(
			m_am_tools,
			cf_str_EAP_read_all_configurations.get_field()) == true)
	{
		// Copy all special configurations to data.

		eap_process_tlv_message_data_c message(m_am_tools);

		if (message.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			// cf_str_EAP_default_type_hex_data and cf_str_EAP_server_default_type_hex_data

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// Now there are enabled EAP type, we need to take the first EAP type from the arrary.
			SEapExpandedType * expandedEAPType = m_enabled_expanded_eap_array[0]; //First item.

			status = value_data.set_copy_of_buffer(
				expandedEAPType->EapExpandedType.Ptr(),
				KExpandedEapTypeSize);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_default_type_hex_data.get_field(),
				eap_configure_type_hex_data,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_server_default_type_hex_data.get_field(),
				eap_configure_type_hex_data,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_UMA_profile, cf_str_EAP_AKA_UMA_profile,
			// cf_str_EAP_GSMSIM_wait_eap_success_packet and cf_str_EAP_AKA_wait_eap_success_packet

			TInt val(1);

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = value_data.set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_UMA_profile.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_UMA_profile.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_wait_eap_success_packet.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_wait_eap_success_packet.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_UMA_realm_prefix and cf_str_EAP_AKA_UMA_realm_prefix

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			if (iRealmPrefix != 0)
			{
				// Set uma realm prefix of EAP-SIM and EAP-AKA.
				status = value_data.set_copy_of_buffer(iRealmPrefix->Ptr(), iRealmPrefix->Length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);			
				}
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_UMA_realm_prefix.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_UMA_realm_prefix.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_use_manual_realm, cf_str_EAP_AKA_use_manual_realm

			TInt val(1);

			if(iManualRealm == NULL || (iManualRealm && (iManualRealm->Length() == 0)))
			{
				val = 0;
			}

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = value_data.set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_use_manual_realm.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_use_manual_realm.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_manual_realm and cf_str_EAP_AKA_manual_realm

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			if(iManualRealm != NULL)
			{
				// ManualRealm of EAP-SIM and EAP-AKA.
				status = value_data.set_copy_of_buffer(iManualRealm->Ptr(), iManualRealm->Length());
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);			
				}
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_manual_realm.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_manual_realm.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_use_manual_username, cf_str_EAP_AKA_use_manual_username

			// Use ManualUsername of EAP-SIM and EAP-AKA.
			TInt val(1);
			if (iManualUsername == NULL || (iManualUsername->Length() == 0))
				{
				val = 0;
				}

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = value_data.set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_use_manual_username.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_use_manual_username.get_field(),
				eap_configure_type_boolean,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_manual_username and cf_str_EAP_AKA_manual_username

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// ManualUsername of EAP-SIM and EAP-AKA.
			if (iManualUsername != NULL)
				{
				status = value_data.set_copy_of_buffer(iManualUsername->Ptr(), iManualUsername->Length());
				if (status != eap_status_ok)
					{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);			
					}
				}
			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_manual_username.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_manual_username.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_TRACE_output_file_name

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
#ifdef USE_EAP_VPN_FILETRACE

			status = value_data.set_copy_of_buffer(m_trace_log_file_name);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
#endif
			status = add_configuration_data(
				&message,
				cf_str_EAP_TRACE_output_file_name.get_field(),
				eap_configure_type_string,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_max_session_validity_time and cf_str_EAP_AKA_max_session_validity_time

			u32_t session_validity_time_in_seconds(43200ul);

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = value_data.set_copy_of_buffer(reinterpret_cast<u8_t*>(&session_validity_time_in_seconds), sizeof(session_validity_time_in_seconds));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_max_session_validity_time.get_field(),
				eap_configure_type_u32_t,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_max_session_validity_time.get_field(),
				eap_configure_type_u32_t,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_CORE_wait_eap_request_type_timeout

			u32_t wait_eap_request_type_timeout_in_milli_seconds(30000ul);

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = value_data.set_copy_of_buffer(reinterpret_cast<u8_t*>(&wait_eap_request_type_timeout_in_milli_seconds), sizeof(wait_eap_request_type_timeout_in_milli_seconds));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_CORE_wait_eap_request_type_timeout.get_field(),
				eap_configure_type_u32_t,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		{
			// cf_str_EAP_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array and cf_str_EAP_AKA_2_digit_mnc_map_of_mcc_of_imsi_array

			eap_variable_data_c value_data(m_am_tools);
			if (value_data.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			// 2-digit MNC configuration of EAP-SIM and EAP-AKA.
			status = value_data.set_copy_of_buffer((u32_t*) K2DigitMncMccList, sizeof(K2DigitMncMccList));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array.get_field(),
				eap_configure_type_u32array,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}

			status = add_configuration_data(
				&message,
				cf_str_EAP_AKA_2_digit_mnc_map_of_mcc_of_imsi_array.get_field(),
				eap_configure_type_u32array,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);			
			}
		}

		status = data->set_copy_of_buffer(
			message.get_message_data(),
			message.get_message_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		eap_variable_data_c wanted_field(m_am_tools);

		status = wanted_field.set_buffer(
			field->get_field(),
			field->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return status;
		}


		if (wanted_field.compare(
			cf_str_EAP_default_type_hex_data.get_field()->get_field(),
			cf_str_EAP_default_type_hex_data.get_field()->get_field_length()) == 0
		|| wanted_field.compare(
			cf_str_EAP_server_default_type_hex_data.get_field()->get_field(),
			cf_str_EAP_server_default_type_hex_data.get_field()->get_field_length()) == 0)
		{
			// We need to return here the next EAP type we should try

			if(m_enabled_expanded_eap_array.Count() < 1)
			{
				// No enabled EAP types.
				
				// Send WLM notification because there is no way that the authentication
				// can be successful if we don't have any EAP types to use...
				if (m_is_client)
				{
					EAP_TRACE_ERROR(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: No configured EAP types or all tried unsuccessfully.\n")));
				}

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);				
			}

			// Now there are enabled EAP type, we need to take the first EAP type from the arrary.
			SEapExpandedType * expandedEAPType = m_enabled_expanded_eap_array[0]; //First item.
			
			status = data->set_copy_of_buffer(expandedEAPType->EapExpandedType.Ptr(), KExpandedEapTypeSize);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);			
			}
			
			// This is to check if this is the requested EAP type.
			
			eap_expanded_type_c tmpExpEAPType;
			
			// This is to make the tmpExpEAPType in 8 byte string with correct vendor type and vendor id details.
			status = eap_expanded_type_c::read_type(m_am_tools,
													0, // index should be zero here.
													expandedEAPType->EapExpandedType.Ptr(),
													KExpandedEapTypeSize,
													&tmpExpEAPType);
			if (status != eap_status_ok)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::read_configure: eap_expanded_type_c::write_type failed \n")));
			
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			if(tmpExpEAPType == iRequestedEapType)
			{			
				EAP_TRACE_DATA_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("CEapVpnInterfaceImplementation::StartL:Trying EAP type:"),
					expandedEAPType->EapExpandedType.Ptr(),
					expandedEAPType->EapExpandedType.Size()));
			}							

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_UMA_profile.get_field()->get_field(),
				cf_str_EAP_GSMSIM_UMA_profile.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
					cf_str_EAP_AKA_UMA_profile.get_field()->get_field(),
					cf_str_EAP_AKA_UMA_profile.get_field()->get_field_length()) == 0)
		{
			// Set uma profile of EAP-SIM and EAP-AKA.
			TInt val(1);
			status = data->set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_wait_eap_success_packet.get_field()->get_field(),
				cf_str_EAP_GSMSIM_wait_eap_success_packet.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
					cf_str_EAP_AKA_wait_eap_success_packet.get_field()->get_field(),
					cf_str_EAP_AKA_wait_eap_success_packet.get_field()->get_field_length()) == 0)
		{
			// Set wait eap success of EAP-SIM and EAP-AKA.
			TInt val(1);
			status = data->set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_UMA_realm_prefix.get_field()->get_field(),
				cf_str_EAP_GSMSIM_UMA_realm_prefix.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
					cf_str_EAP_AKA_UMA_realm_prefix.get_field()->get_field(),
					cf_str_EAP_AKA_UMA_realm_prefix.get_field()->get_field_length()) == 0)
		{
			// Set uma realm prefix of EAP-SIM and EAP-AKA.

			if (iRealmPrefix != 0)
			{
				status = data->set_copy_of_buffer(iRealmPrefix->Ptr(), iRealmPrefix->Length());
			}
			else
			{
				status = eap_status_illegal_configure_field;
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_use_manual_realm.get_field()->get_field(),
				cf_str_EAP_GSMSIM_use_manual_realm.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
					cf_str_EAP_AKA_use_manual_realm.get_field()->get_field(),
					cf_str_EAP_AKA_use_manual_realm.get_field()->get_field_length()) == 0)
		{
			// Use ManualRealm of EAP-SIM and EAP-AKA.
			TInt val(1);
			if(iManualRealm == NULL || (iManualRealm && (iManualRealm->Length() == 0)))
			{
				val = 0;
			}
			status = data->set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_manual_realm.get_field()->get_field(),
				cf_str_EAP_GSMSIM_manual_realm.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
					cf_str_EAP_AKA_manual_realm.get_field()->get_field(),
					cf_str_EAP_AKA_manual_realm.get_field()->get_field_length()) == 0)
		{
			// ManualRealm of EAP-SIM and EAP-AKA.
			if(iManualRealm != 0)
			{
				status = data->set_copy_of_buffer(iManualRealm->Ptr(), iManualRealm->Length());
			}
			else
			{
				status = eap_status_illegal_configure_field;
			}

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_use_manual_username.get_field()->get_field(),
				cf_str_EAP_GSMSIM_use_manual_username.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
				cf_str_EAP_AKA_use_manual_username.get_field()->get_field(),
				cf_str_EAP_AKA_use_manual_username.get_field()->get_field_length()) == 0)
		{
			// Use ManualUsername of EAP-SIM and EAP-AKA.
			TInt val(1);
			if(iManualUsername == NULL)
			{
				val = 0;
			}
			if (iManualUsername && (iManualUsername->Length() == 0))
			{
				val = 0;
			}
			status = data->set_copy_of_buffer((u8_t*) &val, sizeof(TUint));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_manual_username.get_field()->get_field(),
				cf_str_EAP_GSMSIM_manual_username.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
				cf_str_EAP_AKA_manual_username.get_field()->get_field(),
				cf_str_EAP_AKA_manual_username.get_field()->get_field_length()) == 0)
		{
			// ManualUsername of EAP-SIM and EAP-AKA.
			if(iManualUsername != NULL)
				{
				status = data->set_copy_of_buffer(iManualUsername->Ptr(), iManualUsername->Length());
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);		
				}
		}
		else if (wanted_field.compare(
				cf_str_EAP_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array.get_field()->get_field(),
				cf_str_EAP_GSMSIM_2_digit_mnc_map_of_mcc_of_imsi_array.get_field()->get_field_length()) == 0
			|| wanted_field.compare(
					cf_str_EAP_AKA_2_digit_mnc_map_of_mcc_of_imsi_array.get_field()->get_field(),
					cf_str_EAP_AKA_2_digit_mnc_map_of_mcc_of_imsi_array.get_field()->get_field_length()) == 0)
		{
			// 2-digit MNC configuration of EAP-SIM and EAP-AKA.
			status = data->set_copy_of_buffer((u32_t*) K2DigitMncMccList, sizeof(K2DigitMncMccList));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
#ifdef USE_EAP_VPN_FILETRACE
		else if (wanted_field.compare(
				cf_str_EAP_TRACE_output_file_name.get_field()->get_field(),
				cf_str_EAP_TRACE_output_file_name.get_field()->get_field_length()) == 0)
		{
			// Trace output file name.
			status = data->set_copy_of_buffer(
				m_trace_log_file_name);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
#endif
		else if (wanted_field.compare(
					cf_str_EAP_GSMSIM_max_session_validity_time.get_field()->get_field(),
					cf_str_EAP_GSMSIM_max_session_validity_time.get_field()->get_field_length()) == 0
				|| wanted_field.compare(
					cf_str_EAP_AKA_max_session_validity_time.get_field()->get_field(),
					cf_str_EAP_AKA_max_session_validity_time.get_field()->get_field_length()) == 0)
		{
			u32_t session_validity_time_in_seconds(43200ul);

			status = data->set_copy_of_buffer(reinterpret_cast<u8_t*>(&session_validity_time_in_seconds), sizeof(session_validity_time_in_seconds));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else if (wanted_field.compare(
					cf_str_EAP_CORE_wait_eap_request_type_timeout.get_field()->get_field(),
					cf_str_EAP_CORE_wait_eap_request_type_timeout.get_field()->get_field_length()) == 0)
		{
			u32_t wait_eap_request_type_timeout_in_milli_seconds(30000ul);

			status = data->set_copy_of_buffer(reinterpret_cast<u8_t*>(&wait_eap_request_type_timeout_in_milli_seconds), sizeof(wait_eap_request_type_timeout_in_milli_seconds));

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);		
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CEapVpnInterfaceImplementation: read_configure(): Unknown configuration\n"),
				field->get_field(),
				field->get_field_length()));
		}
	}

	// Otherways just use the default value
	m_am_tools->trace_configuration(
		status,
		field,
		data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * The write_configure() function writes the configuration data identified
 * by the field string of field_length bytes length. Adaptation module must direct
 * the action to some persistent store.
 * @see abs_eap_base_type_c::write_configure().
 */
eap_status_e CEapVpnInterfaceImplementation::write_configure(
	const eap_configuration_field_c * const /*field*/,
	eap_variable_data_c * const /*data*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_not_supported;
}

//--------------------------------------------------

/**
 * This is notification of internal state transition.
 * This is used for notifications, debugging and protocol testing.
 * The primal notifications are eap_state_variable_e::eap_state_authentication_finished_successfully
 * and eap_state_variable_e::eap_state_authentication_terminated_unsuccessfully.
 * These two notifications are sent from EAP-protocol layer (eap_protocol_layer_e::eap_protocol_layer_eap).
 * These two notifications tells the end state of authentication session. These are the only
 * reliable indications of the final status of authentication session.
 * You MUST NOT make decision based on the return value of abs_eap_stack_interface_c::packet_process().
 */
void CEapVpnInterfaceImplementation::state_notification(
                                const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::state_notification() = %d=%s\n"),
		state->get_current_state(),
		eap_state_notification_c::get_state_string(eap_protocol_layer_eap, state->get_current_state())));

	if (m_block_packet_sends_and_notifications == true)
	{
		// Notification block is active.		
		EAP_TRACE_ALWAYS(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("state_notification: notification ignored because Disassociated() was called.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return;
	}

	// Check if this is EAP layer notification
	if(state->get_protocol_layer() == eap_protocol_layer_eap)
	{
		switch (state->get_current_state())
		{
		case eap_state_none:
			break;
		case eap_state_identity_request_sent:
			// This is for server only so no need to notify WLM.
			break;
		case eap_state_identity_request_received:
			break;
		case eap_state_identity_response_received:
			// This is for server only so no need to notify WLM.
			break;
		case eap_state_authentication_finished_successfully:
		{
			increment_authentication_counter();
			m_successful_authentications++;	
	
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent: ESuccess.\n")));

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: Indication sent: ESuccess\n")));
			iCaller->EapIndication(ESuccess);
			break;
		}
		case eap_state_authentication_terminated_unsuccessfully:
		{
			increment_authentication_counter();
			m_failed_authentications++;

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CEapVpnInterfaceImplementation: Indication sent: EFailure\n")));

			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Indication sent: EFailure.\n")));
			iCaller->EapIndication(EFailure);
			break;
		}
		default:
			break;
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

/**
 * The set_timer() function initializes timer to be elapsed after time_ms milliseconds.
 * @param initializer is pointer to object which timer_expired() function will
 * be called after timer elapses.
 * @param id is identifier which will be returned in timer_expired() function.
 * The user selects and interprets the id for this timer.
 * @param data is pointer to any user selected data which will be returned in timer_expired() function.
 * @param time_ms is the time of timer in milli seconds.
 *
 * Adaptation module internally implements the timer.
 */
eap_status_e CEapVpnInterfaceImplementation::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (m_am_tools != 0)
	{
		status = m_am_tools->am_set_timer(
			p_initializer, 
			p_id, 
			p_data,
			p_time_ms);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

/**
 * The cancel_timer() function cancels the timer id initiated by initializer.
 * @param initializer is pointer to object which set the cancelled timer.
 * @param id is identifier which will be returned in timer_expired() function.
 * The user selects and interprets the id for this timer.
 *
 * Adaptation module internally implements the timer.
 */
eap_status_e CEapVpnInterfaceImplementation::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (m_am_tools != 0)
	{
		status = m_am_tools->am_cancel_timer(
			p_initializer, 
			p_id);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

/**
 * The cancel_all_timers() function cancels all timers.
 * User should use this in termination of the stack before
 * the adaptation module of tools is deleted.
 * Preferred mode is to cancel each timer directly
 * using cancel_timer() function.
 *
 * Adaptation module internally implements the timer.
 */
eap_status_e CEapVpnInterfaceImplementation::cancel_all_timers()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_ok);

	if (m_am_tools != 0)
	{
		status = m_am_tools->am_cancel_all_timers();
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status;
}

//--------------------------------------------------

/**
 * This function queries the validity of EAP-type.
 * Lower layer should return eap_status_ok if this EAP-type is supported.
 * @param eap_type is the requested EAP-type.
 */
eap_status_e CEapVpnInterfaceImplementation::check_is_valid_eap_type(const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_illegal_eap_type);

	for (int i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
	{
		TBuf8<KExpandedEapTypeSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapVpnInterfaceImplementation::check_is_valid_eap_type:Enabled expanded EAP type at index=%d\n"),
			 i));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled expanded EAP type:"),
			tmpExpEAP.Ptr(),
			tmpExpEAP.Size()));

		// This is for one expanded EAP type (for the above one).
		eap_expanded_type_c expandedEAPType;
				
		// Read the expanded EAP type details for this item in m_enabled_expanded_eap_array.
		eap_status_e status = eap_expanded_type_c::read_type(m_am_tools,
												0,
												tmpExpEAP.Ptr(),
												tmpExpEAP.Size(),
												&expandedEAPType);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (eap_type == expandedEAPType)
		{
			// This is Allowed and Valid.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	} // End of for()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This function queries the list of supported EAP-types.
 * Lower layer should return eap_status_ok if this call succeeds.
 * @param eap_type_list will include the list of supported EAP-types. Each value in list
 * is type of u32_t and represent one supported EAP-type. List consists of subsequent u32_t type values.
 */
eap_status_e CEapVpnInterfaceImplementation::get_eap_type_list(eap_array_c<eap_type_value_e> * const eap_type_list)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status(eap_status_illegal_eap_type);

	status = eap_type_list->reset();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_header_string_c eap_string;
	EAP_UNREFERENCED_PARAMETER(eap_string);

	// This function is same as get_selected_eap_types in behavior.

	// We need to return only the EAP types available as enabled types.
	// It means only the ones available in m_enabled_expanded_eap_array.
	
	for (TInt i = 0; i < m_enabled_expanded_eap_array.Count(); i++)
	{	
		TBuf8<KExpandedEapTypeSize> tmpExpEAP(m_enabled_expanded_eap_array[i]->EapExpandedType);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CEapVpnInterfaceImplementation::get_eap_type_list:Enabled expanded EAP type at index=%d\n"),
			 i));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Enabled expanded EAP type:"),
			tmpExpEAP.Ptr(),
			tmpExpEAP.Size()));

		// This is for one expanded EAP type (for the above one).
		eap_expanded_type_c * expandedEAPType = new eap_type_value_e();
				
		// Read the expanded EAP type details from an item in m_enabled_expanded_eap_array.
		status = eap_expanded_type_c::read_type(m_am_tools,
												0,
												tmpExpEAP.Ptr(),
												tmpExpEAP.Size(),
												expandedEAPType);
		if (status != eap_status_ok)
		{
			delete expandedEAPType;
			expandedEAPType = 0;

			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		// Add EAP-type to list.		
		status = eap_type_list->add_object(expandedEAPType, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}		

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("get_eap_type_list():added EAP-type=0xfe%06x%08x=%s\n"),
			expandedEAPType->get_vendor_id(),
			expandedEAPType->get_vendor_type(),
			eap_header_string_c::get_eap_type_string(*expandedEAPType)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return eap_status_ok;
}

//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::add_rogue_ap(eap_array_c<eap_rogue_ap_entry_c> & /*rogue_ap_list*/)
{
	// Not used, but might be called
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	TInt err = KErrNone;

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_vpn_if::add_rogue_ap()\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
	return EAP_STATUS_RETURN(m_am_tools, m_am_tools->convert_am_error_to_eapol_error(err));
}

//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::restart_authentication(
	const eap_am_network_id_c * const /*receive_network_id*/,
	const bool /*is_client_when_true*/,
	const bool /*force_clean_restart*/,
	const bool /*from_timer*/)
{
	// Not used, but might be called
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_vpn_if::restart_authentication()\n")));

	eap_status_e status = eap_status_ok;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------

//
eap_status_e CEapVpnInterfaceImplementation::asynchronous_init_remove_eap_session(
	const eap_am_network_id_c * const /* send_network_id */)
{
	// eapol_core_c object does not support asynchronous_init_remove_eap_session().
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

//
eap_status_e CEapVpnInterfaceImplementation::set_session_timeout(
	const u32_t /* session_timeout_ms */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}


//--------------------------------------------------

//
eap_status_e CEapVpnInterfaceImplementation::timer_expired(
	const u32_t id,
	void * /*data*/)
{
	// Not used, but might be called
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapVpnInterfaceImplementation::timer_expired()\n")));

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: [0x%08x]->eap_vpn_if::timer_expired(id 0x%02x).\n"),
		this,
		id));

	switch (id)
	{
	case EAPOL_AM_CORE_TIMER_DELETE_STACK_ID:
		{
			EAP_TRACE_ALWAYS(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("EAPOL_AM_CORE_TIMER_DELETE_STACK_ID elapsed: Delete stack.\n")));

			cancel_all_timers();

			// Delete stack
			if (iEapCore != 0)
			{
				iEapCore->shutdown();
				delete iEapCore;
				iEapCore = 0;				
			}
			m_stack_marked_to_be_deleted = false;

			// Re-activates timer queue.
			eap_status_e status = m_am_tools->re_activate_timer_queue();
			if (status != eap_status_ok)
			{
				EAP_TRACE_ALWAYS(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: re_activate_timer_queue() failed, status = %d\n")));
			}

			break;
		}

	default:
		break;
	} // switch()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

//
eap_status_e CEapVpnInterfaceImplementation::timer_delete_data(
    const u32_t /*id*/, void * /*data*/)
{
	// Not used, but might be called
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_ALWAYS(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("TIMER: [0x%08x]->eap_vpn_if::timer_delete_data().\n"),
		this));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

// -----------------------------------------------------------------------------
// CleanupImplArray
// -----------------------------------------------------------------------------
//
void CEapVpnInterfaceImplementation::CleanupImplArray( TAny* aAny )
{
	RImplInfoPtrArray* implArray = 
		reinterpret_cast<RImplInfoPtrArray*>( aAny );

	implArray->ResetAndDestroy();
	implArray->Close();
}

//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::wait_complete_get_802_11_authentication_mode()
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::wait_complete_get_802_11_authentication_mode(): calls iWait.Start()\n")));

	iWait.Start();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::WaitCompletion(): iWait.Start() returns, m_completion_status=%d\n"),
		m_completion_status));

	return EAP_STATUS_RETURN(m_am_tools, m_completion_status);
}

//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::complete_get_802_11_authentication_mode(
	const eap_status_e completion_status,
	const eap_am_network_id_c * const /* receive_network_id */,
	const eapol_key_802_11_authentication_mode_e /* mode */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_get_802_11_authentication_mode(): calls iWait.AsyncStop()\n")));


	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	m_completion_status = completion_status;

	// This is needed to continue the execution after iWait->Start(); 
	iWait.AsyncStop();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapGeneralSettingsImpl::complete_get_802_11_authentication_mode(): iWait.AsyncStop() returns, m_completion_status=%d\n"),
		m_completion_status));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, m_completion_status);
}

//--------------------------------------------------

eap_status_e CEapVpnInterfaceImplementation::complete_remove_eap_session(
	const bool /* complete_to_lower_layer */,
	const eap_am_network_id_c * const /* receive_network_id */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

eap_status_e CEapVpnInterfaceImplementation::save_simple_config_session(
	const simple_config_state_e /* state */,
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const /* credential_array */,
	const eap_variable_data_c * const /* new_password */,
	const simple_config_Device_Password_ID_e /* Device_Password_ID */,
	const simple_config_payloads_c * const /* other_configuration */
	)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_ASSERT(m_am_tools->get_global_mutex()->get_is_reserved() == true);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

//
eap_session_core_base_c * CEapVpnInterfaceImplementation::new_eap_core_client_message_if_c(
	abs_eap_am_tools_c * const tools,
	abs_eap_session_core_c * const partner,
	const bool is_client_when_true,
	const u32_t MTU)
{
	eap_am_message_if_c *client_if = new_eap_am_client_message_if_c(
		tools,
		is_client_when_true,
		MTU);

	eap_automatic_variable_c<eap_am_message_if_c> automatic_server_if(
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
				(EAPL("ERROR: calls: eap_session_core_base_c::new_eap_core_client_message_if_c(): client_if->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			(void) client_if->shutdown();
		}

		return 0;
	}

	eap_core_client_message_if_c * new_session_core = new eap_core_client_message_if_c(tools, client_if, partner, is_client_when_true);

	eap_automatic_variable_c<eap_core_client_message_if_c> automatic_new_session_core(
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
				(EAPL("ERROR: calls: eap_session_core_base_c::new_eap_core_client_message_if_c(): new_session_core->shutdown(): %s.\n"),
				(is_client_when_true == true) ? "client": "server"));

			new_session_core->shutdown();
		}

		(void) client_if->shutdown();

		return 0;
	}

	client_if->set_partner(new_session_core);

	automatic_server_if.do_not_free_variable();
	automatic_new_session_core.do_not_free_variable();

	return new_session_core;
}

//--------------------------------------------------

// End
