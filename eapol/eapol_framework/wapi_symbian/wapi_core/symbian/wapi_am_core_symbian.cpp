/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wapi_core/symbian/wapi_am_core_symbian.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 78.1.7 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

// This is enumeration of EAPOL source code.
#if defined(USE_WAPI_MINIMUM_RELEASE_TRACES)
	#undef WAPI_FILE_NUMBER_ENUM
	#define WAPI_FILE_NUMBER_ENUM 148 
	#undef WAPI_FILE_NUMBER_DATE 
	#define WAPI_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_WAPI_MINIMUM_RELEASE_TRACES)

// INCLUDE FILES

#include <f32file.h>
#include <mmtsy_names.h>
#include <utf.h>   
#include "eap_am_memory.h"

#include "eap_variable_data.h"
#include "eap_automatic_variable.h"
#include "eap_tools.h"
#include "eap_type_all.h"

#include "eapol_ethernet_header.h"
#include "ethernet_core.h"
#include "eap_am_tools_symbian.h"
#include "abs_eap_am_tools.h"
#include "WapiDbDefaults.h"
#include "eap_crypto_api.h"
#include "eap_header_string.h"
#include "eap_am_file_input_symbian.h"
#include "eap_rogue_ap_entry.h"
#include "abs_eap_state_notification.h"
#include "eapol_session_key.h"
#include "eap_buffer.h"
#include "eap_config.h"
#include "wapi_am_core_symbian.h"
#include "abs_wapi_am_core.h"
#include "abs_ec_am_certificate_store.h"
#include "certificate_store_db_symbian.h"
#include "ec_cs_tlv_header.h"
#include "eap_array_algorithms.h"
#include "ec_certificate_store.h"
#include "wapi_asn1_der_parser.h"
#include "wapi_core.h"

#if defined(USE_WAPI_FILECONFIG)
	#include "eap_file_config.h"
#endif //#if defined(USE_EAP_FILECONFIG)

#if defined (USE_EAPOL_KEY_STATE) 
	#include "eapol_key_state.h"	
#endif

#if defined( WAPI_USE_UI_NOTIFIER )   		        
#include "wapnotifier_struct.h"
#endif


// LOCAL CONSTANTS
const TUint KMaxConfigStringLength = 256;

const TUint KMaxDeviceSeedLength = RMobilePhone::KPhoneManufacturerIdSize+
RMobilePhone::KPhoneModelIdSize+
//RMobilePhone::KPhoneRevisionIdSize+
RMobilePhone::KPhoneSerialNumberSize;
const TUint KMaxDeviceSeedSize = 2*KMaxDeviceSeedLength;

// ================= MEMBER FUNCTIONS =======================

wapi_am_core_symbian_c::wapi_am_core_symbian_c(
	abs_eap_am_tools_c *const aTools,
	abs_wapi_am_core_c * const aPartner,
	const bool aIsClientWhenTrue ) 
    : CActive( CActive::EPriorityStandard )
    , iState( EWapiStatesNumber )
    , iAmTools( aTools )
    , iInReferences( iAmTools )
    , iReferencesAndDataBlocks( iAmTools )    
    , iPartner( aPartner )
    , iCertStorePartner( NULL )
    , iCertificateStoreDb( NULL )
    , iCsPassword ( iAmTools )
    , iCancelCalled( EFalse )
    , m_authentication_counter(0u)
    , m_successful_authentications(0u)
    , m_failed_authentications(0u)
    , m_is_valid(false)
    , m_is_client(aIsClientWhenTrue)
    , m_first_authentication(true)
    , m_self_disassociated(false)
    , m_fileconfig(0)
    , iEapVarData(iAmTools)
    {
    }	

//--------------------------------------------------

wapi_am_core_symbian_c::wapi_am_core_symbian_c(
	abs_eap_am_tools_c *const aTools,
	abs_wapi_am_core_c *const aPartner,
	CCertificateStoreDatabase *aCertificateStoreDb,
    const bool aIsClientWhenTrue)
    : CActive( CActive::EPriorityStandard )
    , iState( EWapiStatesNumber )
    , iAmTools( aTools )
    , iInReferences( iAmTools )
    , iReferencesAndDataBlocks( iAmTools )    
    , iPartner( aPartner )
    , iCertStorePartner( NULL )
    , iCertificateStoreDb( aCertificateStoreDb )
    , iCsPassword ( iAmTools )
    , iCancelCalled( EFalse )
    , m_authentication_counter(0u)
    , m_successful_authentications(0u)
    , m_failed_authentications(0u)
    , m_is_valid(false)
    , m_is_client(aIsClientWhenTrue)
    , m_first_authentication(true)
    , m_self_disassociated(false)
    , m_fileconfig(0)
    , iEapVarData(iAmTools)
    {
    }   
	

void wapi_am_core_symbian_c::ConstructL()
{
	if (iPartner == 0)
	{
		User::Leave(KErrGeneral);
	}
	// Activate Scheduler
    CActiveScheduler::Add( this );

    if (iAmTools->configure() != eap_status_ok)
	{
		User::Leave(KErrGeneral);
	}

	iWapiDeviceSeed  = new (ELeave) eap_variable_data_c(iAmTools);

	iWapiDeviceSeed->reset();

	iImportedFilenames.Reset();
		
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI INITIALISATION\n")));	
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("====================\n")));	

    EAP_TRACE_ALWAYS(
        iAmTools,
        TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
        (EAPL("wapi_am_core_symbian_c::ConstructL: %s: \n"),
        (m_is_client == true ? "client": "server")));

	// Create the cert store if it wasn't passed as a parameter
	if ( iCertificateStoreDb == NULL )
	    {
	    iCertificateStoreDb = CCertificateStoreDatabase::NewL( iAmTools );
	    }
	
	m_ssid = new (ELeave) eap_variable_data_c(iAmTools);

	// reset sertificate array
	iCertArray.Reset();
	
	if (m_is_client)
	    {
#if defined(USE_WAPI_FILECONFIG)
	    {
		EAP_TRACE_DEBUG(
			iAmTools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("Initialize file configuration.\n")));
			eap_am_file_input_symbian_c fileio(iAmTools);

		eap_variable_data_c file_name_c_data(iAmTools);

		eap_status_e status(eap_status_process_general_error);

		eap_const_string const FILECONFIG_FILENAME_C
		= "c:\\system\\data\\wapi.conf";

		status = file_name_c_data.set_copy_of_buffer(
		        FILECONFIG_FILENAME_C,
		        iAmTools->strlen(FILECONFIG_FILENAME_C));
		if (status != eap_status_ok)
		    {
		    EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
		    User::Leave(iAmTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iAmTools, status)));
		    }

		status = file_name_c_data.add_end_null();
		if (status != eap_status_ok)
		    {
		    EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
		    User::Leave(iAmTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iAmTools, status)));
		    }
    

		eap_variable_data_c file_name_z_data(iAmTools);

		eap_const_string const FILECONFIG_FILENAME_Z
            = "z:\\private\\101F8EC5\\wapi.conf";

		status = file_name_z_data.set_copy_of_buffer(
		        FILECONFIG_FILENAME_Z,
				iAmTools->strlen(FILECONFIG_FILENAME_Z));
		if (status != eap_status_ok)
			{
			EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
			User::Leave(iAmTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iAmTools, status)));
			}

		status = file_name_z_data.add_end_null();
		if (status != eap_status_ok)
		    {
		    EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
		    User::Leave(iAmTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iAmTools, status)));
			}
		

		if (status == eap_status_ok)
		    {
			// First try open from C: disk.
			status = fileio.file_open(
				&file_name_c_data,
				eap_file_io_direction_read);
			if (status == eap_status_ok)
			    {
				EAP_TRACE_DEBUG(
					iAmTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Opens configure file %s\n"),
					file_name_c_data.get_data(file_name_c_data.get_data_length())));
			    }
			else if (status != eap_status_ok)
			    {
				// Second try open from Z: disk.
				status = fileio.file_open(
					&file_name_z_data,
					eap_file_io_direction_read);
				if (status == eap_status_ok)
				    {
					EAP_TRACE_DEBUG(
						iAmTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("Opens configure file %s\n"),
						 file_name_z_data.get_data(file_name_z_data.get_data_length())));
				    }
			    }

			if (status == eap_status_ok)
			    {
				// Some of the files were opened.

				m_fileconfig = new eap_file_config_c(iAmTools);
				if (m_fileconfig != 0
					&& m_fileconfig->get_is_valid() == true)
				    {
					status = m_fileconfig->configure(&fileio);
					if (status != eap_status_ok)
					    {
						EAP_TRACE_DEBUG(
							iAmTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: Configure read from %s failed.\n"),
							file_name_c_data.get_data(file_name_c_data.get_data_length())));
					    }
					else
					    {
						EAP_TRACE_DEBUG(
							iAmTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("Configure read from %s\n"),
							file_name_c_data.get_data(file_name_c_data.get_data_length())));
					    }
				    }
				else
				    {
					// No file configuration.
					delete m_fileconfig;
					m_fileconfig = 0;

					EAP_TRACE_DEBUG(
						iAmTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: Cannot create configure object for file %s\n"),
						file_name_c_data.get_data(file_name_c_data.get_data_length())));
				    }
			    }
			else
			    {
				EAP_TRACE_DEBUG(
					iAmTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Cannot open configure file neither %s nor %s\n"),
					file_name_c_data.get_data(file_name_c_data.get_data_length()),
					file_name_z_data.get_data(file_name_z_data.get_data_length())));
			    }
		    }
	    }

#endif //#if defined(USE_WAPI_FILECONFIG)

#if defined(USE_WAPI_HARDWARE_TRACE)
		// Disable traces.
		iAmTools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);

		eap_variable_data_c trace_output_file(iAmTools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_output_file_name.get_field(),
			&trace_output_file);
		if (status == eap_status_ok
			&& trace_output_file.get_is_valid_data() == true)
		    {
			status = iAmTools->set_trace_file_name(&trace_output_file);
			if (status == eap_status_ok)
			    {
				// OK, set the default trace mask.
				iAmTools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_debug
					| eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error);
			    }
		    }
#endif //#if defined(USE_WAPI_HARDWARE_TRACE)


    EAP_TRACE_DEBUG(
        iAmTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("To Configure wapi_am_core_symbian_c\n")));
        
		eap_status_e status = configure();
		if (status != eap_status_ok)
		    {
			User::Leave(KErrGeneral);
		    }
        
	    }	
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Configured WAPI AM...\n")));

	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("Created timer...\n")));

	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("========================\n")));

	set_is_valid();

#if defined( WAPI_USE_UI_NOTIFIER )	
    TInt err = iNotifier.Connect();
    if ( err != KErrNone )
        {
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    		"ERROR: wapi_am_core_symbian_c::ConstructL() \
    		Failed to connect to notifier server, err=%d.\n" ), err ) );	
        return;
        }
    if ( !iNotifierDataToUser )
    	{
    	iNotifierDataToUser = new(ELeave) TWapiUiNotifierInfo;	
    	}
	if ( !iNotifierDataPckgToUser )
		{
		iNotifierDataPckgToUser = new(ELeave) TPckg<TWapiUiNotifierInfo> (*iNotifierDataToUser);	
		}
	if ( !iNotifierDataFromUser )
		{
		iNotifierDataFromUser = new(ELeave) TWapiUiNotifierInfo;
		}
	if ( !iNotifierDataPckgFromUser )
		{
		iNotifierDataPckgFromUser = new(ELeave) TPckg<TWapiUiNotifierInfo> (*iNotifierDataFromUser);			
		}
#endif

    } // wapi_am_core_symbian_c::ConstructL()


//--------------------------------------------------

void wapi_am_core_symbian_c::set_am_certificate_store_partner(abs_ec_am_certificate_store_c * const partner)
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
          "wapi_am_core_symbian_c::set_am_certificate_store_partner" ) ) );
	iCertStorePartner = partner;
	 
    }

//--------------------------------------------------

wapi_am_core_symbian_c* wapi_am_core_symbian_c::NewL(
	abs_eap_am_tools_c* const aTools,
	abs_wapi_am_core_c * const aPartner,
	const bool aIsClient)
    {
	wapi_am_core_symbian_c* self = new(ELeave) wapi_am_core_symbian_c(
		aTools, aPartner, aIsClient );
	CleanupStack::PushL(self);
	self->ConstructL();

	if (self->get_is_valid() != true)
	    {
		User::Leave(KErrGeneral);
	    }

	CleanupStack::Pop();
	return self;
    }

wapi_am_core_symbian_c* wapi_am_core_symbian_c::NewL(
	abs_eap_am_tools_c* const aTools,
    abs_wapi_am_core_c * const aPartner,
    CCertificateStoreDatabase* aCertificateStoreDb,
    const bool aIsClient)
    {
    wapi_am_core_symbian_c* self = new(ELeave) wapi_am_core_symbian_c(
        aTools, aPartner, aCertificateStoreDb, aIsClient);
    CleanupStack::PushL(self);
    self->ConstructL();

    if (self->get_is_valid() != true)
        {
        User::Leave(KErrGeneral);
        }

    CleanupStack::Pop();
    return self;
    }


// ---------------------------------------------------------
// wapi_am_core_symbian_c::~wapi_am_core_symbian_c()
// ---------------------------------------------------------
//
wapi_am_core_symbian_c::~wapi_am_core_symbian_c()
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::~wapi_am_core_symbian_c IN\n" ) ) );

	if (m_is_client)
	    {
#if defined(USE_EAP_FILECONFIG)
	    delete m_fileconfig;
	    m_fileconfig = 0;
#endif //#if defined(USE_EAP_FILECONFIG)
	    }
	delete iWapiDeviceSeed;
	    	
#if defined( WAPI_USE_UI_NOTIFIER )	        
	iNotifier.Close();
    delete iNotifierDataToUser;
    delete iNotifierDataPckgToUser;	
	delete iNotifierDataFromUser;
	delete iNotifierDataPckgFromUser;
#endif // WAPI_USE_UI_NOTIFIER
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::~wapi_am_core_symbian_c OUT\n" ) ) );

    } // wapi_am_core_symbian_c::~wapi_am_core_symbian_c()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::shutdown()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::shutdown()
    {
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_am_core_symbian_c::shutdown()\n")));

	// cancel asynch. request of AO
	iCancelCalled = ETrue;
	if ( IsActive() )
		{
		Cancel();
		}
	// Cancel timer	
	cancel_timer(this, EWapiInitCertificateStoreTimerId);
    cancel_timer(this, EWapiAddCertificateFileTimerId);
    cancel_timer(this, EWapiReadCertificateStoreDataTimerId);
    cancel_timer(this, EWapiWriteCertificateStoreDataTimerId);

   delete m_ssid;
   m_ssid = NULL;
   
   EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_am_core_symbian_c::shutdown() delete Arrays\n")));

   TInt count=0;
   while (count < iCertArray.Count())
       {
       if (iCertArray[count].iData != NULL)
           {
           delete iCertArray[count].iData;
           iCertArray[count].iData = NULL;
           }
       if (iCertArray[count].iReference != NULL)
           {
           delete iCertArray[count].iReference;
           iCertArray[count].iReference= NULL;
           }
       count ++;
       }
		

	iCertArray.Reset();

	delete m_fileconfig;
	m_fileconfig = 0;
	
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI EXITING.\n")));
	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);	

	return eap_status_ok;
	
    } // wapi_am_core_symbian_c::shutdown()


// ================= protected: from CActive =======================
    

// ---------------------------------------------------------
// wapi_am_core_symbian_c::RunL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::RunL()
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"wapi_am_core_symbian_c::RunL() IN, iStatus=%d, iState=%d.\n"),
		iStatus.Int(), iState ) );

	if ( iStatus.Int() != KErrNone )
	    {
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "ERROR: wapi_am_core_symbian_c::RunL() iStatus=%d" ),
	        iStatus.Int() ) );
		return;
	    }
	  
    if ( iState == EWapiHandlingDeviceSeedQueryState )
		{
	    CompleteHandlingDeviceSeedQueryState();	    
        iState = EWapiStatesNumber;
		}
#if defined( WAPI_USE_UI_NOTIFIER )   		        
    else if ( iState == EWapiQueryCertFilePasswordState )
    	{
        CompleteQueryCertFilePassword();
    	}
    else if ( iState == EWapiQueryImportFilePasswordState )
    	{
        CompleteQueryImportFilePassword();
    	}
#endif // WAPI_USE_UI_NOTIFIER 
    else
    	{
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "ERROR: wapi_am_core_symbian_c::RunL() State is not supported, \
		    iState = %d." ), iState ) );
    	}
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::RunL() OUT.\n" ) ) );
    
    } // wapi_am_core_symbian_c::RunL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::DoCancel()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::DoCancel()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::DoCancel() IN\n" ) ) );

	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);

#if defined( WAPI_USE_UI_NOTIFIER )   		        
	iNotifier.CancelNotifier( KWapiNotifierUid );
#endif
	
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_am_core_symbian_c::DoCancel()\n")));

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::DoCancel() OUT\n" ) ) );

    }

//--------------------------------------------------

void wapi_am_core_symbian_c::set_is_valid()
    {
	m_is_valid = true;
    }

bool wapi_am_core_symbian_c::get_is_valid()
    {
	return m_is_valid;
    }

//--------------------------------------------------

//
void wapi_am_core_symbian_c::state_notification(const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);

	if(state->get_protocol_layer() == eap_protocol_layer_general)
	    {
		if (state->get_current_state() == eap_general_state_authentication_cancelled)
		    {
			// Authentication was cancelled. Cannot continue.
			EAP_TRACE_DEBUG(
				iAmTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Authentication was cancelled. WAPI_AM_CORE_TIMER_FAILED_COMPLETELY_ID.\n")));

            }
		else if (state->get_current_state() == eap_general_state_configuration_error)
		    {
			// Configuration error. Cannot continue.
			EAP_TRACE_DEBUG(
				iAmTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Configuration error. WAPI_AM_CORE_TIMER_FAILED_COMPLETELY_ID.\n")));

		    }
	    }

	
	if(state->get_protocol_layer() == eap_protocol_layer_eapol)
	{
		switch (state->get_current_state())
		{
		case eapol_state_no_start_response:
			EAP_TRACE_DEBUG(
				iAmTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Indication NOT sent to WLM: ENoResponse.\n")));
			break;
		default:
			break;
		}
	}
	else if(state->get_protocol_layer() == eap_protocol_layer_eapol_key)
	{
		switch (state->get_current_state())
		{
		case eapol_key_state_802_11i_authentication_terminated_unsuccessfull:
			{					

				// Consider WAPI layer failures fatal.
				EAP_TRACE_ERROR(
					iAmTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: Unsuccessful authentication on WAPI level.\n")));
				EAP_TRACE_DEBUG(
					iAmTools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("Indication NOT sent to WLM: EThisAPFailed.\n")));
			}
			break;
		case eapol_key_state_802_11i_authentication_finished_successfull:
			{					
				EAP_TRACE_ALWAYS(
					iAmTools,
					TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
					(EAPL("EAPOL_KEY: %s: Authentication SUCCESS\n"),
					(m_is_client == true ? "client": "server")));
			}
			break;
		default:
			break;
		}
	}	
	

	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
}


// ---------------------------------------------------------
// wapi_am_core_symbian_c::timer_expired()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::timer_expired(
	const u32_t id, void * /* data */)
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"wapi_am_core_symbian_c::timer_expired() IN, id = %d.\n"),
		id ) );
	
	iWapiCompletionStatus = eap_status_ok;
	eap_status_e status = eap_status_ok;
	switch ( id )
	    {
	    case EWapiInitCertificateStoreTimerId:
	    	{
	    	status = ProcessInitCertificateStore();
	    	break;
	    	}
	    case EWapiAddCertificateFileTimerId:
	    	{
	        status = ProcessAddCertificateFile();
	        break;
	    	}
	    case EWapiReadCertificateStoreDataTimerId:
	    	{	        
            status = ProcessReadCertificateStoreData();
            break;
	    	}
	    case EWapiWriteCertificateStoreDataTimerId:
	    	{
            status = ProcessWriteCertificateStoreData();
            break;	    	
	    	}
	    default:
	    	{
	    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			    "ERROR: wapi_am_core_symbian_c::timer_expired() unknown \
			    id = %d.\n"), id ) );
	    	}
	    } // switch
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::timer_expired() OUT, status = %d.\n" ),
	    status ) );
	return status;

    } // wapi_am_core_symbian_c::timer_expired()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::timer_delete_data()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::timer_delete_data(
	const u32_t id, void *data)
    {
    return eap_status_ok;
    }
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e wapi_am_core_symbian_c::configure()
    {	
	EAP_TRACE_DEBUG(
		iAmTools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("wapi_am_core_symbian_c::configure()\n")));


	//----------------------------------------------------------
	{		
		eap_variable_data_c EAP_TRACE_disable_traces(iAmTools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_disable_traces.get_field(),
			&EAP_TRACE_disable_traces);
		if (status == eap_status_ok
			&& EAP_TRACE_disable_traces.get_is_valid_data() == true)
		    {
			u32_t *disable_traces = reinterpret_cast<u32_t *>(
				EAP_TRACE_disable_traces.get_data(sizeof(u32_t)));
			if (disable_traces != 0
				&& *disable_traces != 0)
			    {
				iAmTools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);
			    }
			else
			    {
				// OK, set the default trace mask.
				iAmTools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_debug
					| eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error);
			    }
		    }
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_only_trace_masks_always_and_error(iAmTools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_only_trace_masks_always_and_error.get_field(),
			&EAP_TRACE_activate_only_trace_masks_always_and_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_only_trace_masks_always_and_error.get_is_valid_data() == true)
		    {
			u32_t *activate_trace_mask_always
				= reinterpret_cast<u32_t *>(
					EAP_TRACE_activate_only_trace_masks_always_and_error.get_data(
						sizeof(u32_t)));
			if (activate_trace_mask_always != 0
				&& *activate_trace_mask_always != 0)
			    {
				iAmTools->set_trace_mask(
					eap_am_tools_c::eap_trace_mask_always
					| eap_am_tools_c::eap_trace_mask_error
					);
			    }
		    }
	}

	//----------------------------------------------------------

	{		
		eap_variable_data_c EAP_TRACE_activate_trace_on_error(iAmTools);

		eap_status_e status = read_configure(
			cf_str_EAP_TRACE_activate_trace_on_error.get_field(),
			&EAP_TRACE_activate_trace_on_error);
		if (status == eap_status_ok
			&& EAP_TRACE_activate_trace_on_error.get_is_valid_data() == true)
		    {
			u32_t *activate_trace_on_error = reinterpret_cast<u32_t *>(
				EAP_TRACE_activate_trace_on_error.get_data(sizeof(u32_t)));
			if (activate_trace_on_error != 0
				&& *activate_trace_on_error != 0)
			    {
				iAmTools->set_activate_trace_on_error();
			    }
		    }
	}

    //----------------------------------------------------------
    {       
        eap_variable_data_c EAP_TRACE_disable_traces(iAmTools);

        eap_status_e status = read_configure(
            cf_str_EAP_TRACE_disable_traces.get_field(),
            &EAP_TRACE_disable_traces);
        if (status == eap_status_ok
            && EAP_TRACE_disable_traces.get_is_valid_data() == true)
            {
            u32_t *disable_traces = reinterpret_cast<u32_t *>(
                EAP_TRACE_disable_traces.get_data(sizeof(u32_t)));
            if (disable_traces != 0
                && *disable_traces != 0)
                {
                iAmTools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);
                }
            else
                {
                // OK, set the default trace mask.
                iAmTools->set_trace_mask(
                    eap_am_tools_c::eap_trace_mask_debug
                    | eap_am_tools_c::eap_trace_mask_always
                    | eap_am_tools_c::eap_trace_mask_error);
                }
            }
    }

    //----------------------------------------------------------

    //----------------------------------------------------------

	// All of the configuration options are optional.
	// So we return OK.
	return eap_status_ok;
    }

//--------------------------------------------------

eap_status_e wapi_am_core_symbian_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c * const data)
    {
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);

	if(field->get_field_length() > KMaxConfigStringLength)
	    {
		return eap_status_process_general_error;
	    }
	
	eap_status_e status(eap_status_ok);
	
	eap_variable_data_c type_field(iAmTools);
	eap_variable_data_c type_field_server(iAmTools);
	
#if defined(USE_EAP_FILECONFIG)
		if (m_fileconfig != 0
			&& m_fileconfig->get_is_valid() == true)
		    {
			// Here we could try the final configuration option.
			status = m_fileconfig->read_configure(
				field,
				data);
		    }
#endif //#if defined(USE_EAP_FILECONFIG)

	iAmTools->trace_configuration(
		status,
		field,
		data);

	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iAmTools, status);
    }

//--------------------------------------------------

//
eap_status_e wapi_am_core_symbian_c::set_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id, 
	void * const p_data,
	const u32_t p_time_ms)
    {
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = iAmTools->am_set_timer(
		p_initializer, 
		p_id, 
		p_data,
		p_time_ms);

	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
	return status;
        }

//--------------------------------------------------

//
eap_status_e wapi_am_core_symbian_c::cancel_timer(
	abs_eap_base_timer_c * const p_initializer, 
	const u32_t p_id)
    {
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);
	
	const eap_status_e status = iAmTools->am_cancel_timer(
		p_initializer, 
		p_id);

	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
	return status;
    }

//--------------------------------------------------

//
eap_status_e wapi_am_core_symbian_c::cancel_all_timers()
    {
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);

	const eap_status_e status = iAmTools->am_cancel_all_timers();

	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
	return status;
    }

//--------------------------------------------------

abs_wapi_am_core_c * wapi_am_core_symbian_c::get_am_partner()
	{
	return iPartner;
	}

//--------------------------------------------------

void wapi_am_core_symbian_c::set_am_partner(abs_wapi_am_core_c * const partner)
	{
	iPartner = partner;	
	}
//--------------------------------------------------

eap_status_e wapi_am_core_symbian_c::reset()
	{
	iImportedFilenames.Reset();  
	return eap_status_ok;
	}
//--------------------------------------------------				

eap_status_e wapi_am_core_symbian_c::authentication_finished(
		const bool true_when_successfull)
	{
	return eap_status_ok;
	}

//----------------------------------------------------
// These two methods only because of interface support 
//----------------------------------------------------

eap_status_e wapi_am_core_symbian_c::type_configure_read(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data)
	{
    EAP_TRACE_DATA_DEBUG(
        iAmTools,
        TRACE_FLAGS_DEFAULT,
        (EAPL("Wanted Field"),
                field->get_field(),
                field->get_field_length()));

    return eap_status_ok;
	
	}

//--------------------------------------------------				
eap_status_e wapi_am_core_symbian_c::type_configure_write(
		const eap_configuration_field_c * const field,
		eap_variable_data_c * const data)
	{
	return eap_status_ok;
	
	}


// ================= protected: from ec_am_base_certificate_store_c =======================


// ---------------------------------------------------------
// wapi_am_core_symbian_c::initialize_certificate_store()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::initialize_certificate_store(
	const wapi_completion_operation_e completion_operation )
	{
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(iAmTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("wapi_am_core_symbian_c::initialize_certificate_store IN\n")));
	
	iCompletionOperation = completion_operation;
	
	iWapiCompletionStatus = set_timer(
			this,
			EWapiInitCertificateStoreTimerId, 
			0,
			0);
	
	if (iWapiCompletionStatus != eap_status_ok)
		{
			EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);
		}

	iWapiCompletionStatus = eap_status_pending_request;
			
	EAP_TRACE_DEBUG(iAmTools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_am_type_tls_peap_symbian_c::initialize_certificate_store() OUT\n")));
	
	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);	
	
	} // wapi_am_core_symbian_c::initialize_certificate_store()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::read_certificate_store_data()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::read_certificate_store_data(
	const ec_cs_pending_operation_e in_pending_operation,
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::read_certificate_store_data() IN, \
	    in_pending_operation=%d.\n" ), in_pending_operation ) );
	eap_status_e status = eap_status_ok;
	
	// store args in member vars
	iCsPendingOperation = in_pending_operation;
	
	// store references
	status = copy( in_references,   // original array
		           &iInReferences,  // copy array
	               iAmTools,        // am tools
		           false );         // reset copy array
	if ( status != eap_status_ok )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "ERROR: wapi_am_core_symbian_c::read_certificate_store_data() \
		    Copying of in_references array failed, status=%d.\n" ), status ) );
		    return status;
		}
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::read_certificate_store_data() set timer for \
        EWapiReadCertificateStoreDataTimerId\n" ) ) );
	status = set_timer( this, EWapiReadCertificateStoreDataTimerId,
		0, 0 );
	if ( status != eap_status_ok )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "wapi_am_core_symbian_c::read_certificate_store_data() \
		    failed to set timer, status=%d.\n" ), status ) );		
		    return status;
		}
	else
		{
		status = eap_status_pending_request;
		}
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::read_certificate_store_data() OUT, \
        status=%d.\n" ), status ) );
	return status;
	
	} // wapi_am_core_symbian_c::read_certificate_store_data()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::write_certificate_store_data()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::write_certificate_store_data(
	const bool when_true_must_be_synchronous_operation,
	const ec_cs_pending_operation_e in_pending_operation,
	EAP_TEMPLATE_CONST eap_array_c<ec_cs_data_c> * const in_references_and_data_blocks )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::write_certificate_store_data() IN, \
        when_true_must_be_synchronous_operation=%d.\n" ),
        when_true_must_be_synchronous_operation ) );
	eap_status_e status = eap_status_ok;
	
	// store args in member vars
	iCsPendingOperation = in_pending_operation;
	
	eap_variable_data_c aFilename(iAmTools);
	
    TInt i = 0;
    while (i< iImportedFilenames.Count())
        {
        aFilename.set_copy_of_buffer(iImportedFilenames[i].Ptr(), iImportedFilenames[i].Size());
        
        TRAPD(err, CompleteAddImportedCertificateFileL(&aFilename));
        if (err)
            {
            // Continue to next operation
            }
        iImportedFilenames[i].Zero();
        i++;
        }
    iImportedFilenames.Reset();  


	// store references
	status = copy( in_references_and_data_blocks, // original array
		           &iReferencesAndDataBlocks,     // copy array
	               iAmTools,                      // am tools
		           false );                       // reset copy array
	if ( status != eap_status_ok )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "ERROR: wapi_am_core_symbian_c::write_certificate_store_data() \
		    Copying of in_references array failed, status=%d.\n" ), status ) );
		}
	
    if ( when_true_must_be_synchronous_operation )
    	{ 
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "wapi_am_core_symbian_c::write_certificate_store_data() \
            Synchronous writing.\n" ) ) );
    	// no timer is set, writing is done here
    	ProcessWriteCertificateStoreData();
    	}
    else
    	{ 
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    	    "wapi_am_core_symbian_c::write_certificate_store_data() \
    	    Asynchronous writing. Set timer for EWapiWriteCertificateStoreDataTimerId\n" ) ) );
    	status = set_timer( this, EWapiWriteCertificateStoreDataTimerId,
    		0, 0 );
    	if ( status != eap_status_ok )
    		{
    		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    		    "wapi_am_core_symbian_c::write_certificate_store_data() \
    		    failed to set timer, status=%d.\n" ), status ) );		
    		}
    	else
    		{
    		status = eap_status_pending_request;
    		}
    	}
    
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::write_certificate_store_data() OUT\n" ) ) );

	return status;	
	} // wapi_am_core_symbian_c::write_certificate_store_data()

//--------------------------------------------------	

eap_status_e wapi_am_core_symbian_c::complete_add_imported_certificate_file(
	const eap_status_e in_completion_status,
	const eap_variable_data_c * const in_imported_certificate_filename)
	{
        iWapiCompletionStatus = eap_status_ok;
	
    EAP_TRACE_DEBUG_SYMBIAN(
        (_L("wapi_am_core_symbian_c::complete_add_imported_certificate_file in_completion_status=%d"),
                in_completion_status));       

    TBuf8<256> aFile;
    aFile.Copy(in_imported_certificate_filename->get_data(in_imported_certificate_filename->get_data_length()), in_imported_certificate_filename->get_data_length());
    iImportedFilenames.Append(aFile);
    
    TInt i = 0;
    while (i< iImportedFilenames.Count())
        {
        EAP_TRACE_DATA_DEBUG(
                iAmTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("eap_am_type_tls_peap_symbian_c::complete_add_imported_certificate_file: Got Filenames "),
                    iImportedFilenames[i].Ptr(),
                    iImportedFilenames[i].Size()));
        i++;
        }

    iWapiCompletionStatus = set_timer(
             this,
             EWapiAddCertificateFileTimerId, 
             0,
             0);

    return iWapiCompletionStatus;
	
	}

	//--------------------------------------------------	
void wapi_am_core_symbian_c::CompleteAddImportedCertificateFileL(const eap_variable_data_c * const in_imported_certificate_filename)
    {
    RFs aFs;
     aFs.Connect( KFileServerDefaultMessageSlots );

     HBufC8* buf = HBufC8::NewLC(in_imported_certificate_filename->get_data_length());
     TPtr8 bufPtr = buf->Des();

     if (in_imported_certificate_filename->get_data_length() != 0)
         {
         bufPtr.Copy(in_imported_certificate_filename->get_data(), in_imported_certificate_filename->get_data_length());
         }

     HBufC* FilePath = HBufC::NewLC(KMaxFileName);
     TPtr FilePathPtr = FilePath->Des();
     HBufC8* FilePath8 = HBufC8::NewLC(KMaxFileName);
     TPtr8 FilePathPtr8 = FilePath8->Des();
     
     FilePathPtr8.Zero();
     FilePathPtr8.Append(KCertificateStoreImportDir);
     FilePathPtr8.Append(bufPtr);

     FilePathPtr.Copy(FilePathPtr8);


     EAP_TRACE_DATA_DEBUG(
             iAmTools,
         TRACE_FLAGS_DEFAULT,
         (EAPL("eap_am_type_tls_peap_symbian_c::CompleteAddImportedCertificateFileL: Filename "),
         FilePathPtr.Ptr(),
         FilePathPtr.Size()));
  
     if (m_is_client)
         {
         EAP_TRACE_DATA_DEBUG(
                 iAmTools,
             TRACE_FLAGS_DEFAULT,
             (EAPL("eap_am_type_tls_peap_symbian_c::CompleteAddImportedCertificateFileL: Delete File"),
             FilePathPtr.Ptr(),
             FilePathPtr.Size()));
     
         aFs.SetAtt(FilePathPtr, NULL, KEntryAttReadOnly);
         if(aFs.Delete(FilePathPtr)!= KErrNone)
             {
             EAP_TRACE_DATA_DEBUG(
                     iAmTools,
                     TRACE_FLAGS_DEFAULT,
                     (EAPL("eap_am_type_tls_peap_symbian_c::CompleteAddImportedCertificateFileL: Couldn't delete file"),
                             FilePathPtr.Ptr(),
                             FilePathPtr.Size()));
     
     
             iWapiCompletionStatus = eap_status_file_does_not_exist;
             }
         }
     else
         {
         RDbNamedDatabase& db = iCertificateStoreDb->GetCertificateStoreDb();
         RDbView view;   
         // Leave if the view preparation still fails
         HBufC* buf3 = HBufC::NewLC(KMaxSqlQueryLength);
         TPtr sqlStatement2 = buf3->Des();
         _LIT(KSQLQueryRow2, "SELECT * FROM %S");
         sqlStatement2.Format(KSQLQueryRow2, &KCsWapiCertFileTable);

         EAP_TRACE_DATA_DEBUG_SYMBIAN( (
             "wapi_am_core_symbian_c::CompleteAddImportedCertificateFileL() sqlStatement",
             sqlStatement2.Ptr(), 
             sqlStatement2.Size() ) );    

         User::LeaveIfError ( view.Prepare( db, TDbQuery(sqlStatement2), TDbWindow::EUnlimited, RDbView::EInsertOnly ));
         CleanupStack::PopAndDestroy( buf3 );
         CleanupClosePushL(view);
         User::LeaveIfError(view.EvaluateAll());

         // Use the data insertion function to update data and reference
         CDbColSet* colSet = view.ColSetL();
         CleanupStack::PushL( colSet );

         view.InsertL();

         TDbColNo colNo = KDefaultColumnNumberOne;
         view.SetColL( colNo, bufPtr );

         view.PutL(); 

         CleanupStack::PopAndDestroy( colSet );
         CleanupStack::PopAndDestroy( &view );        

         }
     CleanupStack::PopAndDestroy(FilePath8); 
     CleanupStack::PopAndDestroy(FilePath); 
     CleanupStack::PopAndDestroy(buf);

    }

eap_status_e wapi_am_core_symbian_c::complete_remove_certificate_store(
	const eap_status_e in_completion_status)
	{
	return eap_status_ok;
	
	}

	//--------------------------------------------------		

eap_status_e wapi_am_core_symbian_c::cancel_certificate_store_store_operations()
	{
	return eap_status_ok;
	
	}

//--------------------------------------------------	

eap_status_e wapi_am_core_symbian_c::set_session_timeout(
	const u32_t session_timeout_ms)
	{
	return eap_status_ok;
	
	}

// ---------------------------------------------------------
// wapi_am_core_symbian_c::CreateDeviceSeedAsync()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::CreateDeviceSeedAsync()
{	
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("wapi_am_core_symbian_c::CreateDeviceSeedAsynch-Start ActiveStatus=%d"),
		IsActive()));		
	
	if ( IsActive() )
	{
		EAP_TRACE_DEBUG_SYMBIAN(
			(_L("wapi_am_core_symbian_c: Already active when tried to create device seed")));		
		
		return eap_status_device_busy;
	}

	eap_status_e status(eap_status_ok);	
	
	iState = EWapiHandlingDeviceSeedQueryState;
		
	// Create MMETEL connection.
	TRAPD(error, CreateMMETelConnectionL());
	if(error !=KErrNone)
	{
		return iAmTools->convert_am_error_to_eapol_error(error);
	}
	
   	iPhone.GetPhoneId( iStatus, iDeviceId ); 

	SetActive();
	return status;
} // wapi_am_core_symbian_c::CreateDeviceSeedAsynch()

//--------------------------------------------------

TInt wapi_am_core_symbian_c::CreateMMETelConnectionL()
{
	EAP_TRACE_BEGIN(iAmTools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Creating MMETel connection.\n")));

	TInt errorCode = KErrNone;
	
	// MMETel need to be connected only once.    
    if( !iMMETELConnectionStatus )
    {
		RTelServer::TPhoneInfo phoneInfo;
		TInt phoneCount = 0;

		// Connect to ETel server
		User::LeaveIfError( iServer.Connect() ); 	
		
	    EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Connected to ETel server.\n")));	

		// This function loads an ETel TSY module, mmtsy.
		errorCode = iServer.LoadPhoneModule( KMmTsyModuleName );	
		
	    EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Loaded phone module.\n")));	    
		
		if ( errorCode != KErrNone && errorCode != KErrAlreadyExists )
		{
			User::Leave( errorCode );
		}

		iServer.SetExtendedErrorGranularity( RTelServer::EErrorExtended );

		// This function retrieves the total number of phones supported by all 
		// the currently loaded ETel (TSY) modules.
		User::LeaveIfError( iServer.EnumeratePhones( phoneCount ) );	
		
		EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Number of phones supported by the loaded ETel = %d.\n"), phoneCount));
		
		// This function retrieves information associated with the specified phone
		while ( ( phoneCount-- ) && ( phoneInfo.iName != KMmTsyPhoneName ) ) 
		{ 
			User::LeaveIfError( iServer.GetPhoneInfo( phoneCount, phoneInfo ) );		
			
		    EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Got phone info.\n")));
		} 

		// This function opens a phone subsession by name. ("DefaultPhone").
		User::LeaveIfError( iPhone.Open( iServer, phoneInfo.iName ) );	
		
	    EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Opened phone subsession.\n")));
		
		// MMETel connected and the phone module loaded fine.	
		iMMETELConnectionStatus = ETrue; 	
    }
    else
    {
    	// MMETel already connected.
	    EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("MMETel connected once already.\n")));
    }
	    
	EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
    
    return errorCode;	
}

//--------------------------------------------------				

void wapi_am_core_symbian_c::DisconnectMMETEL()
	{
	    if( iMMETELConnectionStatus )
	    {
			EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("Closing RMobilePhone and MMETEL.\n")));
			
			iPhone.Close();
			iServer.Close(); // Phone module is unloaded automatically when RTelServer session is closed
			
			iMMETELConnectionStatus = EFalse;
	    }
	    else
	    {
			EAP_TRACE_DEBUG(iAmTools, TRACE_FLAGS_DEFAULT, (EAPL("RMobilePhone and MMETEL already closed.\n")));    	
	    }	
	}


// ================= private: New, timer expired process methods =======================


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ProcessInitCertificateStore()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::ProcessInitCertificateStore()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::ProcessInitCertificateStore() IN\n" ) ) );

	eap_status_e status = eap_status_ok;
	if ( iCertificateStoreDb )
		{
		iCertStorePartner->remove_cached_certificate_store_data();

		TRAPD( err, iCertificateStoreDb->InitializeCertificateStoreL() );
		if ( err != KErrNone )
			{
			EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL (
				"ERROR: wapi_am_core_symbian_c::ProcessInitCertificateStore() Leave, InitializeCertificateStoreL(), err=%d.\n" ), err ) );
			status = iAmTools->convert_am_error_to_eapol_error( err );
			}
		}
	else
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL (
			"ERROR: wapi_am_core_symbian_c::ProcessInitCertificateStore() \
			iCertificateStoreDb is NULL.\n" ) ) );
		status = eap_status_process_general_error;
		}
	
	if ( status == eap_status_ok )
		{
	    status = CreateDeviceSeedAsync();
		}
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::ProcessInitCertificateStore() OUT, \
	    status=%d.\n" ), status ) );
	return status;
	
	} // wapi_am_core_symbian_c::ProcessInitCertificateStore()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ProcessAddCertificateFile()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::ProcessAddCertificateFile()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"wapi_am_core_symbian_c::ProcessAddCertificateFile() IN\n" ) ) );
	eap_status_e status = eap_status_ok;

    TRAPD(err, ImportFilesL());
 	if (err)
		{
		// Complete with ok, even if import fails
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL("ERROR: wapi_am_core_symbian_c::Leave from ImportFilesL () err=%d.\n" ), err ) );
		}
    
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::ProcessAddCertificateFile() OUT\n" ) ) );
    return status;
	
	} // wapi_am_core_symbian_c::ProcessAddCertificateFile()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ProcessReadCertificateStoreData()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::ProcessReadCertificateStoreData()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::ProcessReadCertificateStoreData() IN\n" ) ) );
	
	// read certificate store
    TRAPD( err, ReadCertificateStoreDataL() );
    if ( err != KErrNone )
    	{
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    		"ERROR: wapi_am_core_symbian_c::ProcessReadCertificateStoreData() LEAVE from ReadCertificateStoreDataL(), err=%d" ), err ) );
        iWapiCompletionStatus = iAmTools->convert_am_error_to_eapol_error( err );
     	}

    if ( iWapiCompletionStatus == eap_status_ok || iWapiCompletionStatus == eap_status_pending_request )
    	{
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "wapi_am_core_symbian_c::ProcessReadCertificateStoreData() \
                COMPLETE read_certificate_store_data() request, \
                status=%d, operation=%d" ), iWapiCompletionStatus,
                iCsPendingOperation ) );
        iWapiCompletionStatus = iCertStorePartner->complete_read_certificate_store_data(
                iWapiCompletionStatus,
                iCsPendingOperation,
                &iReferencesAndDataBlocks );
    	}
     else // error status
        {
         iReferencesAndDataBlocks.reset();
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "wapi_am_core_symbian_c::ProcessReadCertificateStoreData() \
                COMPLETE read_certificate_store_data() request, \
                status=%d, operation=%d" ), iWapiCompletionStatus,
                iCsPendingOperation ) );
        iWapiCompletionStatus = iCertStorePartner->complete_read_certificate_store_data(
                iWapiCompletionStatus,
                iCsPendingOperation,
                &iReferencesAndDataBlocks );
    }

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ProcessReadCertificateStoreData() OUT, \
        iWapiCompletionStatus=%d.\n" ), iWapiCompletionStatus ) );
    return iWapiCompletionStatus;
    
	} // wapi_am_core_symbian_c::ProcessReadCertificateStoreData()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ProcessWriteCertificateStoreData()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::ProcessWriteCertificateStoreData()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ProcessWriteCertificateStoreData() IN\n" ) ) );
		
	// write to certificate store
    TRAPD( err, WriteCertificateStoreDataL() );
    if ( err != KErrNone )
    	{
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    	        "ERROR: wapi_am_core_symbian_c::ProcessWriteCertificateStoreData() LEAVE from WriteCertificateStoreDataL(), err=%d" ), err ) );
    	iWapiCompletionStatus = iAmTools->convert_am_error_to_eapol_error( err );
    	}
	
    // process status
    if ( iWapiCompletionStatus == eap_status_ok || iWapiCompletionStatus == eap_status_pending_request )
    	{
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
    		"wapi_am_core_symbian_c::ProcessWriteCertificateStoreData(), \
    		iWapiCompletionStatus=%d\n" ), iWapiCompletionStatus ) );    	
    	}
    else // error
         {
         // complete request!
         iReferencesAndDataBlocks.reset();
         EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::ProcessWriteCertificateStoreData() \
             COMPLETE write_certificate_store_data() request, \
             iWapiCompletionStatus=%d, operation=%d" ),
             iWapiCompletionStatus, iCsPendingOperation ) );
         eap_status_e status = iCertStorePartner->complete_write_certificate_store_data(
             iWapiCompletionStatus,
             iCsPendingOperation );
         if ( status != eap_status_ok )
             {
             // just print an error
             EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                 "ERROR: wapi_am_core_symbian_c::ProcessWriteCertificateStoreData() \
                 complete_write_certificate_store_data(), status=%d" ), status ) );
             }
         }
 
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ProcessWriteCertificateStoreData() OUT\n" ) ) );
    return iWapiCompletionStatus;
	
	} // wapi_am_core_symbian_c::ProcessWriteCertificateStoreData()


// ================= private: New, writing to CS =======================


// ---------------------------------------------------------
// wapi_am_core_symbian_c::WriteCertificateStoreDataL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::WriteCertificateStoreDataL()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::WriteCertificateStoreDataL() IN\n" ) ) );
	
	iWapiCompletionStatus = eap_status_ok;

	for ( u32_t ind = 0ul;
	      ind < iReferencesAndDataBlocks.get_object_count();ind++ )
	    {    
		const ec_cs_data_c* const dataReference = iReferencesAndDataBlocks.
		    get_object( ind );
		if (dataReference->get_is_valid() == false)
		    {
	        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	            "wapi_am_core_symbian_c::WriteCertificateStoreDataL() ERROR: datablock to be written is unvalid!\n" )));
		    return;
		    }
		const ec_cs_data_type_e csDataType = dataReference->get_type();
		
        if (csDataType == NULL)
            {
            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "wapi_am_core_symbian_c::WriteCertificateStoreDataL() ERROR: data type to be written is unvalid!\n" )));
            return;
            }
	
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"wapi_am_core_symbian_c::WriteCertificateStoreDataL() csDataType=%d.\n" ),
			csDataType ) );
		
		if ( dataReference != NULL )
			{
		    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
			    "wapi_am_core_symbian_c::WriteCertificateStoreDataL() dataReference data(value):",
			    dataReference->get_data()->get_data(
			    	dataReference->get_data()->get_data_length() ),
			    dataReference->get_data()->get_data_length() ) );
		
		    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
			    "wapi_am_core_symbian_c::WriteCertificateStoreDataL() data_reference reference:",
			    dataReference->get_reference()->get_data(
			    	dataReference->get_reference()->get_data_length() ),
			    dataReference->get_reference()->get_data_length() ) );
		
		    EAP_TRACE_DEBUG_SYMBIAN( ( _L(
			    "wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
			    change status=%d.\n" ), dataReference->get_change_status() ) );
			}

		if ( dataReference != 0
			&& dataReference->get_is_valid() == true
			&& dataReference->get_type() != ec_cs_data_type_none
			&& dataReference->get_change_status() != ec_cs_data_change_status_none )
		    {			
		    ec_cs_data_change_status_e changeStatus = dataReference->get_change_status();
			switch( csDataType )
			    {
				case ec_cs_data_type_master_key:
				case ec_cs_data_type_reference_counter:
					{
				    WriteCsDataL( dataReference, EFalse );
				    break;
				    }
				case ec_cs_data_type_password: 
				case ec_cs_data_type_device_seed: 
				case ec_cs_data_type_certificate_file_password:
				    {
				    // not saved; nothing to do
				    break;
				    }
				case ec_cs_data_type_ca_certificate_data:
				case ec_cs_data_type_client_certificate_data:
				case ec_cs_data_type_private_key_data:				
                case ec_cs_data_type_client_asu_id:
                case ec_cs_data_type_ca_asu_id:
				    {
				    if ( changeStatus == ec_cs_data_change_status_modified )
				    	{
					    WriteCsDataWithReferenceL( dataReference, EFalse );				    
				    	}
				    else if ( changeStatus == ec_cs_data_change_status_new )
				    	{
					    WriteCsDataWithReferenceL( dataReference, ETrue );				    
				    	}
				    else if ( changeStatus == ec_cs_data_change_status_delete )
				    	{
				    	DeleteCsDataWithReferenceL( dataReference );
				    	}
				    else
				        {
	                    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                        "ERROR: wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
	                        unknown change_status=%d.\n" ), changeStatus ) );
				        }
				    break;
				    }
				default:
					{
					EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
				        "ERROR: wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
				        unknown csDataType=%d.\n" ), csDataType ) );
					iWapiCompletionStatus = eap_status_not_found;
					User::Leave( KErrArgument );
					}
			    } // switch( csDataType )
			
		    } // if ( dataReference != 0...
	    else
	        {
	        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                "Warning: wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
	                failed" ) ) );
	        if ( dataReference != 0 )
	            {
	            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                    "Warning: wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
		                No changes needed, reference: 0x%08x: type %d\n" ),
		                dataReference, dataReference->get_type() ) );

	            if ( dataReference->get_reference() != 0 )
	                 {
	                 EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                         "Warning: wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
	                         unknown reference, or no changes needed" ),
	                         dataReference->get_reference()->get_data(),
	                         dataReference->get_reference()->get_data_length() ) );
	                 }
	            if ( dataReference->get_data() != 0 )
	                {
	                EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                        "Warning: wapi_am_core_symbian_c::WriteCertificateStoreDataL() \
		    	            unknown data" ),
		    	            dataReference->get_data()->get_data(),
		    	            dataReference->get_data()->get_data_length() ) );
	                }
	            }
	        } // else
	    } // for(...)

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::WriteCertificateStoreDataL() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::WriteCertificateStoreDataL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::WriteCsDataWithReferenceL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::WriteCsDataWithReferenceL(
    const ec_cs_data_c* const aDataReference,
    TBool aIsNewEntry )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::WriteCsDataWithReferenceL() IN\n" ) ) );
	
	// Get the data (or value) from the input
	HBufC8* csDbColVal8 = HBufC8::NewLC(
		aDataReference->get_data()->get_data_length() );
	TPtr8 csDbColValPtr8 = csDbColVal8->Des();
	csDbColValPtr8.Copy( aDataReference->get_data()->get_data(),
                         aDataReference->get_data()->get_data_length() );
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::WriteCsDataWithReferenceL() \
		8 bit VALUE from common:",
		csDbColValPtr8.Ptr(), csDbColValPtr8.Size() ) );
	
	// Get the reference from the input
	HBufC8* csDbColRef8 = HBufC8::NewLC(
		aDataReference->get_reference()->get_data_length() );
	TPtr8 csDbColRefPtr8 = csDbColRef8->Des();
	csDbColRefPtr8.Copy( aDataReference->get_reference()->get_data(),
                         aDataReference->get_reference()->get_data_length() );

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::WriteCsDataWithReferenceL() \
		8 bit REFERENCE from common:",
		csDbColRefPtr8.Ptr(), csDbColRefPtr8.Size() ) );
	
	iCertificateStoreDb->SetCsDataByReferenceL(
			aDataReference->get_type(),
			csDbColValPtr8,
			csDbColRefPtr8,
			aIsNewEntry );

    CleanupStack::PopAndDestroy( csDbColRef8 );
	CleanupStack::PopAndDestroy( csDbColVal8 );
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::WriteCsDataWithReferenceL() OUT\n" ) ) );

	} // wapi_am_core_symbian_c::WriteCsDataWithReferenceL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::WriteCsDataL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::WriteCsDataL(
    const ec_cs_data_c* const aDataReference,
    TBool aIsNewEntry )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::WriteCsDataL() IN\n" ) ) );

	// Get the data (or value) from the input
	HBufC8* csDbColVal8 = HBufC8::NewLC(
		aDataReference->get_data()->get_data_length() );
	TPtr8 csDbColValPtr8 = csDbColVal8->Des();
	csDbColValPtr8.Copy( aDataReference->get_data()->get_data(),
                         aDataReference->get_data()->get_data_length() );
	
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::WriteCsDataL() \
		8 bit VALUE from common:",
		csDbColValPtr8.Ptr(), csDbColValPtr8.Size() ) );
		
	iCertificateStoreDb->SetCsDataL(
		aDataReference->get_type(),
		csDbColValPtr8,
        aIsNewEntry );

	CleanupStack::PopAndDestroy( csDbColVal8 );
	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::WriteCsDataL() OUT\n" ) ) );
	
	} /// wapi_am_core_symbian_c::WriteCsDataL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::DeleteCsDataWithReferenceL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::DeleteCsDataWithReferenceL(
	const ec_cs_data_c* const aDataReference )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::DeleteCsDataWithReferenceL() IN\n" ) ) );
	
    // Get the data (or value) from the input
    HBufC8* csDbColVal8 = HBufC8::NewLC(
	    aDataReference->get_data()->get_data_length() );
    TPtr8 csDbColValPtr8 = csDbColVal8->Des();
    csDbColValPtr8.Copy( aDataReference->get_data()->get_data(),
                         aDataReference->get_data()->get_data_length() );

    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
	    "wapi_am_core_symbian_c::DeleteCsDataWithReferenceL() \
	    8 bit VALUE from common:",
	    csDbColValPtr8.Ptr(), csDbColValPtr8.Size() ) );

    // Get the reference from the input
    HBufC8* csDbColRef8 = HBufC8::NewLC(
	    aDataReference->get_reference()->get_data_length() );
    TPtr8 csDbColRefPtr8 = csDbColRef8->Des();
    csDbColRefPtr8.Copy( aDataReference->get_reference()->get_data(),
                         aDataReference->get_reference()->get_data_length() );

    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
	    "wapi_am_core_symbian_c::DeleteCsDataWithReferenceL() \
	    8 bit REFERENCE from common:",
	    csDbColRefPtr8.Ptr(), csDbColRefPtr8.Size() ) );

    iCertificateStoreDb->RemoveCsDataByReferenceL(
		aDataReference->get_type(),
		csDbColValPtr8,
		csDbColRefPtr8 );

    CleanupStack::PopAndDestroy( csDbColVal8 );
    CleanupStack::PopAndDestroy( csDbColRef8 );

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::DeleteCsDataWithReferenceL() OUT\n" ) ) );

	} // wapi_am_core_symbian_c::DeleteCsDataWithReferenceL()


// ================= private: New, reading from CS =======================


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadCertificateStoreDataL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ReadCertificateStoreDataL()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCertificateStoreDataL() IN\n" ) ) );

	iWapiCompletionStatus = eap_status_ok;
	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCertificateStoreDataL() \
        First dataRefType=%d.\n" ), iInReferences.get_object( 0 )->get_type() ) );
    
	iReferencesAndDataBlocks.reset();

	for( u32_t ind = 0ul; ind < iInReferences.get_object_count(); ind++ )
	    {

	    const ec_cs_data_c* const dataReference =
            iInReferences.get_object( ind );
	    
        if (dataReference->get_is_valid() == false)
            {
            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "wapi_am_core_symbian_c::ReadCertificateStoreDataL() ERROR: datablock to be written is unvalid!\n" )));
            return;
            }

        if (iInReferences.get_object( ind )->get_reference()->get_data_length() >0)
	        {
	        EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                "wapi_am_core_symbian_c::ReadCertificateStoreDataL() dataReference:",
                dataReference->get_reference()->get_data(
                    dataReference->get_reference()->get_data_length() ), 
                dataReference->get_reference()->get_data_length() ) );
	        }
		if ( dataReference != 0
			&& dataReference->get_is_valid() == true )
		    {
		    ec_cs_data_type_e dataRefType = dataReference->get_type();
	        if (dataRefType == NULL)
	            {
	            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	                "wapi_am_core_symbian_c::ReadCertificateStoreDataL() ERROR: dataType to be written is unvalid!\n" )));
	            return;
	            }

			EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
				"wapi_am_core_symbian_c::ReadCertificateStoreDataL() \
				dataRefType=%d.\n" ), dataRefType ) );
		    				
			
			iGetAll = EFalse;
			
			switch( dataRefType )
			    {
				case ec_cs_data_type_master_key:         
				case ec_cs_data_type_reference_counter:  
				case ec_cs_data_type_client_asu_id_list: 
				case ec_cs_data_type_ca_asu_id_list:
					{
				    ReadCsDataL( dataReference );
				    break;
				    }
				case ec_cs_data_type_password:
					{
					ReadPasswordL( dataReference );
					break;
					}
				case ec_cs_data_type_device_seed:
				    {
				    ReadDeviceSeedL( dataReference );
				    break;
				    }
				case ec_cs_data_type_certificate_file_password:
				    {
				    ReadCertificateFilePasswordL( dataReference );
				    break;
				    }
				case ec_cs_data_type_ca_certificate_data:     
				case ec_cs_data_type_client_certificate_data: 
				case ec_cs_data_type_private_key_data:				
                case ec_cs_data_type_client_asu_id: 
                case ec_cs_data_type_ca_asu_id:
                case ec_cs_data_type_selected_ca_id:
                case ec_cs_data_type_selected_client_id:
				    {
				    ReadCsDataByReferenceL( dataReference );				    
				    break;
				    }
				default:
					{
					EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
				        "ERROR: wapi_am_core_symbian_c::ReadCertificateStoreDataL() \
				        unknown dataRefType=%d.\n" ), dataRefType ) );
					iWapiCompletionStatus = eap_status_not_found;
					User::Leave( KErrArgument );
					}
			    } // switch( dataRefType )
		    } // if ( dataReference != 0...
	    } // for(...)
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::ReadCertificateStoreDataL() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::ReadCertificateStoreDataL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadCsDataByReferenceL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ReadCsDataByReferenceL(
	const ec_cs_data_c* const aDataReference )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCsDataByReferenceL() IN\n" ) ) );

	HBufC8* outColumnValue = NULL;
        
   	GetCsDataByReferenceL( aDataReference, &outColumnValue );   
   	if ( outColumnValue == NULL )
    	{
    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::ReadCsDataByReferenceL() \
        	outColumnValue is NULL!\n" ) ) );
    	}
   	else
   	    CopyBufToEapVarL( *outColumnValue, iEapVarData );
   	
    // ownership was transfered from CS here
    // delete buffer
    delete outColumnValue;
    outColumnValue = NULL;
    
    AddObjectL( aDataReference, &iEapVarData );
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCsDataByReferenceL() OUT\n" ) ) );
    
    } // wapi_am_core_symbian_c::ReadCsDataByReferenceL()

   
// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadCsDataL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ReadCsDataL(
	const ec_cs_data_c* const aDataReference )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCsDataL() IN\n" ) ) );

	HBufC8* outColumnValue = NULL;
	
	ec_cs_data_type_e dataType = aDataReference->get_type();
	ec_cs_data_type_e dataTypeToCaller(dataType);
    iGetAll = EFalse;    

    if (dataType == ec_cs_data_type_ca_asu_id_list)
		{
		dataTypeToCaller = ec_cs_data_type_ca_asu_id;
		iGetAll = ETrue;	
		}
	if (dataType == ec_cs_data_type_client_asu_id_list)
		{
        dataTypeToCaller = ec_cs_data_type_client_asu_id;
		iGetAll = ETrue;	
		}
	
	if (iGetAll == EFalse)
		{
		TRAPD(err, GetCsDataL( dataType, &outColumnValue ));
		if (err)
		    {
		    delete outColumnValue;
		    outColumnValue = NULL;
		    }
	   	if ( outColumnValue == NULL )
	    	{
	    	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	            "ERROR: wapi_am_core_symbian_c::ReadCsDataL() \
	        	outColumnValue is NULL!\n" ) ) );
	    	}
	   	else
	   	    {
	   	    CopyBufToEapVarL( *outColumnValue, iEapVarData );
	   	    }	   	
	    // ownership was transfered from CS here
	    // delete buffer
      AddObjectL( aDataReference, &iEapVarData );
	    delete outColumnValue;
	    outColumnValue = NULL;
	    
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "wapi_am_core_symbian_c::ReadCsDataL() OUT\n" ) ) );
		}
	else
		{
		iCertArray.Reset();
		TRAPD(err, GetCsTableL( dataType, &outColumnValue, iCertArray ));
        delete outColumnValue;
        outColumnValue = NULL;
		if (err)
		    {
	        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	            "wapi_am_core_symbian_c::GetCsTableL() Leave\n" ) ) );
	        User::Leave(err);
	        }
		else
		    {
            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "wapi_am_core_symbian_c::GetCsTableL() Ok\n" ) ) );
		    TInt aCounter = 0; 
		    
             while (aCounter < iCertArray.Count() )
                {
                 ec_cs_data_c* const csData = new ec_cs_data_c( iAmTools );
                   
                   if ( csData == NULL )
                       {
                       iWapiCompletionStatus = eap_status_allocation_error;
                       EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                           "ERROR: wapi_am_core_symbian_c::AddObjectL() csData is NULL.\n" ) ) );
                       User::Leave( iAmTools->convert_eapol_error_to_am_error(
                           eap_status_allocation_error ) );
                       }
               if (iCertArray[aCounter].iReference->Size()>0 && iCertArray[aCounter].iData->Size()>0)
                    {
                    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                           "wapi_am_core_symbian_c::ReadCsDataL() copy reference\n" ) ) );

                    csData->set_type(dataTypeToCaller);
                    TPtr8 aDbBinaryColumnRefPtr = iCertArray[aCounter].iReference->Des();

                    iWapiCompletionStatus = csData->get_writable_reference()->
                    set_copy_of_buffer( aDbBinaryColumnRefPtr.Ptr(), aDbBinaryColumnRefPtr.Size() );
                    
                    EAP_TRACE_DATA_DEBUG_SYMBIAN(
                        ("wapi_am_core_symbian_c::ReadCsDataL: reference to caller",
                                csData->get_reference()->get_data(csData->get_reference()->get_data_length()), 
                                csData->get_reference()->get_data_length()));
                    if ( iWapiCompletionStatus != eap_status_ok )
                        {
                        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                            "ERROR: wapi_am_core_symbian_c::ReadCsDataL() Failed to add \
                            new object, iWapiCompletionStatus=%d.\n" ), iWapiCompletionStatus ) );
                        delete csData;
                        User::Leave( iAmTools->convert_eapol_error_to_am_error(
                            iWapiCompletionStatus ) );
                        }
                    
                    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                        "wapi_am_core_symbian_c::ReadCsDataL() copy data\n" ) ) );

                    TPtr8 aDbBinaryColumnValuePtr = iCertArray[aCounter].iData->Des();
                     
                    iWapiCompletionStatus = csData->get_writable_data()->
                        set_copy_of_buffer( aDbBinaryColumnValuePtr.Ptr(), aDbBinaryColumnValuePtr.Size() );
                    
                    EAP_TRACE_DATA_DEBUG_SYMBIAN(
                        ("wapi_am_core_symbian_c::ReadCsDataL: data to caller",
                                csData->get_data()->get_data(csData->get_data()->get_data_length()), 
                                csData->get_data()->get_data_length()));

                    iWapiCompletionStatus = iReferencesAndDataBlocks.add_object( csData, true );

                    delete iCertArray[aCounter].iReference;
                    iCertArray[aCounter].iReference = NULL;
                    delete iCertArray[aCounter].iData;
                    iCertArray[aCounter].iData=NULL;
                    
                    if ( iWapiCompletionStatus != eap_status_ok )
                        {
                        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                                "ERROR: wapi_am_core_symbian_c::ReadCsDataL() Failed to add \
                                new object, iWapiCompletionStatus=%d.\n" ), iWapiCompletionStatus ) );
                        delete csData;
                        User::Leave( iAmTools->convert_eapol_error_to_am_error(
                                iWapiCompletionStatus ) );
                        }
                    }
                aCounter++;
                }
             iCertArray.Reset();
             EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "wapi_am_core_symbian_c::ReadCsDataL() OUT\n" ) ) );

		    }
		}
	
    } // wapi_am_core_symbian_c::ReadCsDataL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::GetCsDataByReferenceL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::GetCsDataByReferenceL(
    const ec_cs_data_c* const aDataReference,
    HBufC8** aOutColumnValue )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::GetCsDataByReferenceL() IN\n" ) ) );
    
    const eap_variable_data_c * const reference = aDataReference->get_reference();
	if ( reference == NULL )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::GetCsDataByReferenceL() \
            reference is NULL.\n" ) ) );
		// Can't proceed.
		User::Leave( KErrArgument );		
		}
	if ( reference->get_data_length() <= 0 )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::GetCsDataByReferenceL() \
            reference is empty.\n" ) ) );
		// Can't proceed.
		User::Leave( KErrArgument );		
		}

	HBufC8* reference8 = HBufC8::NewL( reference->get_data_length() );
	TPtr8 referencePtr8 = reference8->Des();				
	referencePtr8.Copy( reference->get_data(), reference->get_data_length() );
	
          
	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::GetCsDataByReferenceL() reference to DB",
		referencePtr8.Ptr(), referencePtr8.Size() ) );			

    ec_cs_data_type_e dataType = aDataReference->get_type();
    
  EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
          "wapi_am_core_symbian_c::GetCsDataByReferenceL() dataType = %d, m_is_client=%d ec_cs_data_type_selected_ca_id=%d ec_cs_data_type_selected_client_id=%d\n" ),
           dataType, m_is_client, ec_cs_data_type_selected_ca_id,ec_cs_data_type_selected_client_id ) );

    if ((dataType == ec_cs_data_type_selected_ca_id || dataType == ec_cs_data_type_selected_client_id) && m_is_client)
        {
        TUint32 aIndex = 0;
        eap_variable_data_c database_reference_index(iAmTools);

        eap_status_e status = iPartner->read_configure(
            cf_str_WAPI_database_reference_index.get_field(),
            &database_reference_index);
        if (status != eap_status_ok
            || database_reference_index.get_is_valid_data() == false
            || database_reference_index.get_data_length() != sizeof(u32_t)
            || database_reference_index.get_data(sizeof(u32_t)) == 0)
            {
            EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
            User::Leave( KErrArgument );        
            }

        u32_t *index = reinterpret_cast<u32_t *>(
            database_reference_index.get_data(sizeof(u32_t)));
        if (index != 0)
            {
            EAP_TRACE_DEBUG(
                iAmTools,
                TRACE_FLAGS_DEFAULT,
                (EAPL("WAPI_Core: this = 0x%08x, %s: wapi_am_core_symbian_c::GetCsDataByReferenceL(): database_reference_index = %d\n"),
                 this,
                 (m_is_client == true ? "client": "server"),
                 *index));
            aIndex = static_cast<TUint32>(*index);
            }

        EAP_TRACE_DEBUG(
             iAmTools,
             TRACE_FLAGS_DEFAULT,
             (EAPL("WAPI_Core: this = 0x%08x, %s: wapi_am_core_symbian_c::GetCsDataByReferenceL(): aIndex = %d\n"),
              this,
              (m_is_client == true ? "client": "server"),
              aIndex));
        
        referencePtr8.SetLength(sizeof(aIndex));
        referencePtr8.Copy( reinterpret_cast<TUint8*>(&aIndex), sizeof(aIndex) );
        
        EAP_TRACE_DATA_DEBUG_SYMBIAN( (
            "wapi_am_core_symbian_c::GetCsDataByReferenceL() reference to DB 2",
            referencePtr8.Ptr(), referencePtr8.Size() ) );          
        }

	// read certificate store
	TRAPD( err, iCertificateStoreDb->GetCsDataByReferenceL( 
			dataType,
			referencePtr8,
			aOutColumnValue
		    ) );

	if ( err != KErrNone )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "wapi_am_core_symbian_c::iCertificateStoreDb->GetCsDataByReferenceL() ERROR: %d\n" ),err ) );
		
        if ( *aOutColumnValue != NULL )
        	{ // some data was allocated by CS
		    delete *aOutColumnValue;
		    *aOutColumnValue = NULL;
		    delete reference8;
		    reference8 = NULL;
       		}
		User::Leave( err );
		}
	
	delete reference8;
	reference8 = NULL;
	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::GetCsDataByReferenceL() OUT\n" ) ) );

    } // wapi_am_core_symbian_c::GetCsDataByReferenceL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::GetCsDataL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::GetCsDataL(
    ec_cs_data_type_e aDataType,
    HBufC8** aOutColumnValue )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::GetCsDataL() IN\n" ) ) );
    
    // read certificate store
	TRAPD( err, iCertificateStoreDb->GetCsDataL( 
		aDataType,         // data type
		aOutColumnValue,// returned column value, memory is allocated in CS
		iCertArray,     // data array for certificate info
		EFalse    		// get all or one row
	    ) );
	
	if ( err != KErrNone )
		{
        if ( *aOutColumnValue != NULL )
        	{
		    delete *aOutColumnValue;
		    *aOutColumnValue = NULL;
        	}
		User::Leave( err );
		}

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::GetCsDataL() OUT\n" ) ) );

    } // wapi_am_core_symbian_c::GetCsDataL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::GetCsTableL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::GetCsTableL( ec_cs_data_type_e aDataType,
  			HBufC8** aOutColumnValue,
  			RArray<SWapiCertEntry>& aArray)
{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::GetCsTableL() IN\n" ) ) );

    // read certificate store
	TRAPD( err, iCertificateStoreDb->GetCsDataL( 
		aDataType,         // data type
		aOutColumnValue,    // returned column value, memory is allocated in CS
		aArray,     // data array for certificate info
		ETrue    		// get all or one row
	    ) );
	
	if ( err != KErrNone )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "wapi_am_core_symbian_c::GetCsTableL() LEAVE FROM iCertificateStoreDb->GetCsDataL\n" ) ) );
        TInt aCounter = 0;	
        while (aCounter < aArray.Count())
	        {
	        delete (aArray[aCounter].iData);
	        aArray[aCounter].iData = NULL;
	        delete (aArray[aCounter].iReference);
	        aArray[aCounter].iReference = NULL;
	        aCounter++;
	        }
		User::Leave( err );
		}

	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::GetCsTableL() OUT\n" ) ) );

	
}

// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadPasswordL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ReadPasswordL(
	const ec_cs_data_c* const aDataReference )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadPasswordL() IN\n" ) ) );
	
	/*
	* NOTE:  The password usage is reserved for future,
	* when there will be config UI support. Use some 
	* temporary password now. When password is really used,
	* delete this code and uncomment below one.
    */
	_LIT( KTempPassword, "12345" );

	iWapiCompletionStatus = iCsPassword.set_copy_of_buffer(
		KTempPassword().Ptr(), KTempPassword().Size() );
	if ( iWapiCompletionStatus != eap_status_ok )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "ERROR: wapi_am_core_symbian_c::ReadPasswordL() \
		    buffer copy failed, status=%d.\n" ), iWapiCompletionStatus ) );
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
			iWapiCompletionStatus ) );
		}

	AddObjectL( aDataReference, &iCsPassword );
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadPasswordL() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::ReadPasswordL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadDeviceSeedL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ReadDeviceSeedL(
	const ec_cs_data_c* const aDataReference )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadDeviceSeedL() IN\n" ) ) );
		
    eap_variable_data_c csDeviceSeed( iAmTools );
    
    iWapiCompletionStatus = csDeviceSeed.set_copy_of_buffer(
    	iWapiDeviceSeed->get_data( iWapiDeviceSeed->get_data_length() ),
    	iWapiDeviceSeed->get_data_length() );
 	if ( iWapiCompletionStatus != eap_status_ok )
	    {		
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		    "ERROR: wapi_am_core_symbian_c::ReadDeviceSeedL() \
			buffer copy failed, status=%d.\n" ), iWapiCompletionStatus ) );
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
			iWapiCompletionStatus ) );
	    }

	EAP_TRACE_DATA_DEBUG_SYMBIAN( (
		"wapi_am_core_symbian_c::ReadDeviceSeedL() Device seed",
		csDeviceSeed.get_data( csDeviceSeed.get_data_length() ),
		csDeviceSeed.get_data_length() ) );

	AddObjectL( aDataReference, &csDeviceSeed );

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadDeviceSeedL() OUT\n" ) ) );
    
    } // wapi_am_core_symbian_c::ReadDeviceSeedL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadCertificateFilePasswordL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ReadCertificateFilePasswordL(
	const ec_cs_data_c* const aDataReference )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCertificateFilePasswordL() IN\n" ) ) );
	
#if defined( WAPI_USE_UI_NOTIFIER )   		        
    StartAsynchRequest( EWapiQueryImportFilePasswordState );
#endif
    
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ReadCertificateFilePasswordL() OUT\n" ) ) );
	
    } // wapi_am_core_symbian_c::ReadCertificateFilePasswordL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::AddObjectL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::AddObjectL(
	const ec_cs_data_c* const aDataReference,
	const eap_variable_data_c* const aData )
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::AddObjectL() IN\n" ) ) );

	ec_cs_data_c* const csData = new ec_cs_data_c( iAmTools );
    
	if ( csData == NULL )
		{
		iWapiCompletionStatus = eap_status_allocation_error;
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::AddObjectL() csData is NULL.\n" ) ) );
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
			eap_status_allocation_error ) );
		}
	
	ec_cs_data_type_e type = aDataReference->get_type();
	csData->set_type( type );					

    // set the reference.
	iWapiCompletionStatus = csData->get_writable_reference()->
	    set_copy_of_buffer( aDataReference->get_reference() );
	if ( iWapiCompletionStatus != eap_status_ok )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::AddObjectL() Failed to copy \
            reference, iWapiCompletionStatus=%d.\n" ), iWapiCompletionStatus ) );
        delete csData;
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
			iWapiCompletionStatus ) );
		}

	iWapiCompletionStatus = csData->get_writable_data()->set_copy_of_buffer(
		aData );
	
     if ( iWapiCompletionStatus != eap_status_ok )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::AddObjectL() Failed to copy \
            master key, iWapiCompletionStatus=%d.\n" ), iWapiCompletionStatus ) );
        delete csData;
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
			iWapiCompletionStatus ) );
		}
	
	iWapiCompletionStatus = iReferencesAndDataBlocks.add_object( csData, true );

	if ( iWapiCompletionStatus != eap_status_ok )
	    {
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::AddObjectL() Failed to add \
            new object, iWapiCompletionStatus=%d.\n" ), iWapiCompletionStatus ) );
		delete csData;
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
			iWapiCompletionStatus ) );
		}
					
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
    	"wapi_am_core_symbian_c::AddObjectL() Added data",
		( csData->get_data() )->get_data( ( csData->get_data() )
			->get_data_length() ),
		( csData->get_data() )->get_data_length() ) );						

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::AddObjectL() OUT\n" ) ) );

	} // wapi_am_core_symbian_c::AddObjectL()


// ================= private: New, start/complete asynch. requests =======================


// ---------------------------------------------------------
// wapi_am_core_symbian_c::StartAsynchRequest()
// ---------------------------------------------------------
//
TBool wapi_am_core_symbian_c::StartAsynchRequest(
	wapi_am_core_symbian_c::TWapiState aState )
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::StartAsynchRequest() IN, \
        aState=%d.\n" ), aState ) );
    TBool status = ETrue;

    if( IsActive() )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::StartAsynchRequest() \
	        AO is active, iState=%d, aState=%d.\n" ), aState, aState ) );
		return EFalse;
		}
	if ( iCancelCalled )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "wapi_am_core_symbian_c::StartAsynchRequest() \
		     Cancel was called.\n" ) ) );
		return EFalse;
		}
    iState = aState;    
    switch ( iState )
        {
#if defined( WAPI_USE_UI_NOTIFIER )   		    
        
        case EWapiQueryCertFilePasswordState:
        	{
        	StartQueryCertFilePassword();
            SetActive();
        	}
        case EWapiQueryImportFilePasswordState:
        	{
        	StartQueryImportFilePassword();
            SetActive();
        	break;
        	}
#endif // WAPI_USE_UI_NOTIFIER

        default:
        	{
    	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
   	            "ERROR: wapi_am_core_symbian_c::StartAsynchRequest() \
   		        State is not supported, iState = %d.\n" ), iState ) );
    		status = EFalse;
            break;
        	}
        }
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::StartAsynchRequest() OUT, \
        status=%d.\n" ), status ) );
    return status;
	
	} // wapi_am_core_symbian_c::StartAsynchRequest()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::StartQueryCertFilePassword()
// ---------------------------------------------------------
//
#if defined( WAPI_USE_UI_NOTIFIER )   		    
void wapi_am_core_symbian_c::StartQueryCertFilePassword()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::StartQueryCertFilePassword() IN\n" ) ) );
    
    iNotifierDataToUser->iState = TWapiUiNotifierState::
        EWapiUiNotifierCsPasswordDialog;
    iNotifier.StartNotifierAndGetResponse( 
        iStatus,
        KWapiNotifierUid,
        *iNotifierDataPckgToUser,
        *iNotifierDataPckgFromUser );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::StartQueryCertFilePassword() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::StartQueryCertFilePassword()
#endif // WAPI_USE_UI_NOTIFIER


// ---------------------------------------------------------
// wapi_am_core_symbian_c::CompleteQueryCertFilePassword()
// ---------------------------------------------------------
//
#if defined( WAPI_USE_UI_NOTIFIER )   		    
void wapi_am_core_symbian_c::CompleteQueryCertFilePassword()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::CompleteQueryCertFilePassword() IN\n" ) ) );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::CompleteQueryCertFilePassword() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::CompleteQueryCertFilePassword()
#endif // WAPI_USE_UI_NOTIFIER


// ---------------------------------------------------------
// wapi_am_core_symbian_c::StartQueryImportFilePassword()
// ---------------------------------------------------------
//
#if defined( WAPI_USE_UI_NOTIFIER )   		    
void wapi_am_core_symbian_c::StartQueryImportFilePassword()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::StartQueryImportFilePassword() IN\n" ) ) );
    
    iNotifierDataToUser->iState = TWapiUiNotifierState::
        EWapiUiNotifierImportFileDialog;
    iNotifier.StartNotifierAndGetResponse( 
        iStatus,
        KWapiNotifierUid,
        *iNotifierDataPckgToUser,
        *iNotifierDataPckgFromUser );
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::StartQueryImportFilePassword() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::StartQueryImportFilePassword()
#endif // WAPI_USE_UI_NOTIFIER


// ---------------------------------------------------------
// wapi_am_core_symbian_c::CompleteQueryImportFilePassword()
// ---------------------------------------------------------
//
#if defined( WAPI_USE_UI_NOTIFIER )   		    
void wapi_am_core_symbian_c::CompleteQueryImportFilePassword()
	{
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::CompleteQueryCertFilePassword() IN\n" ) ) );

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::CompleteQueryImportFilePassword() OUT\n" ) ) );
	
	} // wapi_am_core_symbian_c::CompleteQueryImportFilePassword()
#endif // WAPI_USE_UI_NOTIFIER


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ImportFilesL()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::ImportFilesL()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	"wapi_am_core_symbian_c::ImportFilesL() IN\n" ) ) );

	eap_status_e status = eap_status_ok;

    if ( iCertificateStoreDb == NULL )
        {
        iCertificateStoreDb = CCertificateStoreDatabase::NewL( iAmTools );
        }

    EAP_TRACE_ALWAYS(
        iAmTools,
        TRACE_FLAGS_ALWAYS|TRACE_FLAGS_DEFAULT,
        (EAPL("ImportFilesL: %s: \n"),
        (m_is_client == true ? "client": "server")));

    TBool aFileAlreadyInList = EFalse;
    
    RDbNamedDatabase& db = iCertificateStoreDb->GetCertificateStoreDb();

   // Create a buffer for the ascii strings - initialised in query
    HBufC8* asciibuf = HBufC8::NewLC(KMaxFileName);
    TPtr8 asciiString = asciibuf->Des();
    asciiString.Zero();
    
    // Buffer for unicode parameter
    HBufC* unicodebuf = HBufC::NewLC(KMaxFileName);
    TPtr unicodeString = unicodebuf->Des();
    
     HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
    TPtr sqlStatement = buf->Des();
    _LIT(KSQLQueryRow, "SELECT * FROM %S");
    sqlStatement.Format(KSQLQueryRow, &KCsWapiCertFileTable);
    
    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
        "wapi_am_core_symbian_c::ImportFilesL() sqlStatement for delete",
        sqlStatement.Ptr(), 
        sqlStatement.Size() ) );    

    RDbView view;
    User::LeaveIfError(view.Prepare( db, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EUpdatable));

    CleanupClosePushL(view);
    User::LeaveIfError(view.EvaluateAll()); 
    if (view.FirstL())
        {
        if (m_is_client)
          {
          do
              {
                view.GetL();        
                switch (view.ColType(KDefaultColumnNumberOne))
                    {
                    case EDbColText:                
                        {
                            unicodeString = view.ColDes(KDefaultColumnNumberOne);
                            // Convert to 8-bit
                            if (unicodeString.Size() > 0)
                                {
                                asciiString.Copy(unicodeString);
                                if (status != eap_status_ok)
                                    {
                                    User::Leave(KErrNoMemory);
                                    }
                                } 
                            else 
                                {
                                // Empty field. Do nothing...data remains invalid
                                break;
                                }
                        }     
                     break;
                    case EDbColBinary:
                        {
                        TPtrC8 dbValuePtrC8 = view.ColDes8( KDefaultColumnNumberOne );
                          
                        asciiString.Copy( dbValuePtrC8 );
                        
                        EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                          "ImportFilesL BINARY value from DB",
                          asciiString.Ptr(), asciiString.Size() ) );
                        
                        }
                        break;
                    } // switch
                if (asciiString.Size() > 0)
                    {
                    HBufC* FilePathD = HBufC::NewLC(KMaxFileName);
                    TPtr FilePathPtrD = FilePathD->Des();
                    HBufC8* FilePathD8 = HBufC8::NewLC(KMaxFileName);
                    TPtr8 FilePathPtrD8 = FilePathD8->Des();
                    
                    FilePathPtrD8.Zero();
                    FilePathPtrD8.Append(KCertificateStoreImportDir);
                    FilePathPtrD8.Append(asciiString);
    
                    FilePathPtrD.Copy(FilePathPtrD8);
    
                    EAP_TRACE_DATA_DEBUG(
                            iAmTools,
                        TRACE_FLAGS_DEFAULT,
                        (EAPL("wapi_am_core_symbian_c::ImportFilesL: Delete File"),
                        FilePathPtrD.Ptr(),
                        FilePathPtrD.Size()));
                    RFs aFs;
                    aFs.Connect( KFileServerDefaultMessageSlots );
                    aFs.SetAtt(FilePathPtrD, NULL, KEntryAttReadOnly);

                    if(aFs.Delete(FilePathPtrD)!= KErrNone)
                        {
                        EAP_TRACE_DATA_DEBUG(
                                iAmTools,
                                TRACE_FLAGS_DEFAULT,
                                (EAPL("wapi_am_core_symbian_c::ImportFilesL: Couldn't delete file"),
                                        FilePathPtrD.Ptr(),
                                        FilePathPtrD.Size()));
                         }
                    else
                        {
                        view.DeleteL(); // remove current record
                        }
                    CleanupStack::PopAndDestroy(FilePathD8); 
                    CleanupStack::PopAndDestroy(FilePathD);
                    
                   }
               
              }  while (view.NextL() != EFalse);
          }
        }

    CleanupStack::PopAndDestroy(4); // view, asciibuf, unicodebuf, buf

	CDir* aFiles = NULL;
	 
	RFs aFs;
	aFs.Connect( KFileServerDefaultMessageSlots );

	iWapiCompletionStatus = eap_status_pending_request;

	TInt aFileCounter=0;
	TBool aDirectoryEmpty = false;
	TBool aDirectoryExists = true;
	HBufC* buf2 = HBufC::NewLC(KMaxPath);
    TPtr aFileNamePtr = buf2->Des();
	HBufC8* aFileName8 = HBufC8::NewLC(KMaxFileName);
	TUint aFileSize =0;
	TPtr8 aFileNamePtr8 = aFileName8->Des();
	TBool aBadFile = false;
	HBufC* aPath = HBufC::NewLC(KMaxFileName);
	TPtr aPathPtr = aPath->Des();
	HBufC8* aPath8 = HBufC8::NewLC(KMaxFileName);
	TPtr8 aPathPtr8 = aPath8->Des();
	HBufC8* aReadData = NULL;
	TBool aFileFound(EFalse);
	
	aPathPtr8.Zero();
	aPathPtr8.Append(KCertificateStoreImportDir);

	aPathPtr.Zero();
	aPathPtr.Copy(aPathPtr8);

	if (aFs.GetDir(aPathPtr, KEntryAttNormal, ESortByName, aFiles) == KErrNone)
		{
		EAP_TRACE_DEBUG_SYMBIAN(
				(_L("wapi_am_core_symbian_c::ImportFilesL: aFiles %d"),
						aFiles->Count()));
		
		while (aFileFound  == EFalse && (aFileCounter < aFiles->Count()))
			{
			aDirectoryExists = true;
			aFileAlreadyInList = EFalse;
			if (!((*aFiles)[aFileCounter].IsDir()))
                {
                aDirectoryEmpty = false;
                aFileSize = (*aFiles)[aFileCounter].iSize;

                aFileNamePtr8.Copy((*aFiles)[aFileCounter].iName);

                 EAP_TRACE_DATA_DEBUG(
                         iAmTools,
                         TRACE_FLAGS_DEFAULT,
                         (EAPL("wapi_am_core_symbian_c::ImportFilesL: aFileName"),
                         aFileNamePtr8.Ptr(),
                         aFileNamePtr8.Size()));

                 EAP_TRACE_DEBUG_SYMBIAN(
                        (_L("wapi_am_core_symbian_c::ImportFilesL: aFile size %d"),
                                aFileSize));
                 TInt i = 0;
                 while (i< iImportedFilenames.Count())
                     {
                     if (aFileNamePtr8.Compare(iImportedFilenames[i]) == 0)
                         aFileAlreadyInList = ETrue;
                     i++;
                     }
 
                if (CheckFilenameL(aFileNamePtr8) == EFalse && aFileAlreadyInList == EFalse)
                    {
                    EAP_TRACE_DEBUG_SYMBIAN(
                            (_L("wapi_am_core_symbian_c::ImportFilesL: File not yet Imported -> import")));                  

                    if (aFileSize > KMaxCertificateFileSize)
                        {
                        EAP_TRACE_DEBUG_SYMBIAN(
                               (_L("wapi_am_core_symbian_c::ImportFilesL: aFile size %d bigger than limit %d, do not import"),
                                       aFileSize, KMaxCertificateFileSize));
                        TBuf8<KMaxFileName> aFile; 
                        aFile.Copy(aFileNamePtr8.Ptr(),aFileNamePtr8.Size());
                        iImportedFilenames.Append(aFile);
                        iWapiCompletionStatus = set_timer(
                                 this,
                                 EWapiAddCertificateFileTimerId, 
                                 0,
                                 0);
                        
                        delete aFiles;

                        CleanupStack::PopAndDestroy(aPath8);
                        CleanupStack::PopAndDestroy(aPath);
                        CleanupStack::PopAndDestroy(aFileName8);
                        CleanupStack::PopAndDestroy(buf2);
                        EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
                        return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);
                        }
                    else
                        aFileFound = ETrue;
                    }
                else
                    {
                    EAP_TRACE_DEBUG_SYMBIAN(
                            (_L("wapi_am_core_symbian_c::ImportFilesL: File already imported")));                  
                    }
                }
            aFileCounter++;
			}
			
			if (!aFileFound)
				{
				EAP_TRACE_DEBUG_SYMBIAN(
					(_L("wapi_am_core_symbian_c::ImportFilesL: aDirectoryEmpty or files already imported")));					
				aDirectoryEmpty = true;
				}
			if (aDirectoryEmpty == true ||  aDirectoryExists == false || aFileFound == EFalse)
				{
				if (aDirectoryExists)
					{
                    delete aFiles;
                    iWapiCompletionStatus = iCertStorePartner->complete_initialize_certificate_store( iCompletionOperation );
                    CleanupStack::PopAndDestroy(aPath8);
                    CleanupStack::PopAndDestroy(aPath);
                    CleanupStack::PopAndDestroy(aFileName8);
                    CleanupStack::PopAndDestroy(buf2);
                    EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
                    return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);
					}
				}
			else if(aFileFound != EFalse)
				{
				aPathPtr8.Zero();
				aPathPtr8.Append(KCertificateStoreImportDir);
				aPathPtr8.Append(aFileNamePtr8);
				aPathPtr.Zero();
				aPathPtr.Copy(aPathPtr8);
				
				EAP_TRACE_DEBUG_SYMBIAN(
						(_L("wapi_am_core_symbian_c::ImportFilesL: Read aFile")));	
				
				RFile aFile;
				if(aFile.Open(aFs, aPathPtr, EFileRead)==KErrNone)
					{
					aReadData= HBufC8::NewLC(aFileSize); 
					TPtr8 aReadDataPtr = aReadData->Des();
					aFile.Read(aReadDataPtr);
					aFile.Close();
					
					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("wapi_am_core_symbian_c::ImportFilesL: Copy data")));	
					
					eap_variable_data_c * const in_imported_certificate_data = new eap_variable_data_c(iAmTools);
                    if (in_imported_certificate_data == NULL)
                        {
                        CleanupStack::PopAndDestroy(aReadData);

                        delete aFiles;

                        CleanupStack::PopAndDestroy(aPath8);
                        CleanupStack::PopAndDestroy(aPath);
                        CleanupStack::PopAndDestroy(aFileName8);
                        CleanupStack::PopAndDestroy(buf2);

                        iWapiCompletionStatus = eap_status_allocation_error;
                        EAP_TRACE_DEBUG_SYMBIAN(
                                (_L("wapi_am_core_symbian_c::ImportFilesL: iWapiCompletionStatus != eap_status_ok")));  
                        if (in_imported_certificate_data != NULL)
                            delete in_imported_certificate_data;
                         return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);
                        
                        }

					iWapiCompletionStatus = in_imported_certificate_data->set_copy_of_buffer(aReadDataPtr.Ptr(), aReadDataPtr.Size());

					eap_variable_data_c * const in_imported_certificate_file_name = new eap_variable_data_c(iAmTools);
					if (in_imported_certificate_file_name == NULL)
					    {
	                    CleanupStack::PopAndDestroy(aReadData);

	                    delete aFiles;

	                    CleanupStack::PopAndDestroy(aPath8);
	                    CleanupStack::PopAndDestroy(aPath);
	                    CleanupStack::PopAndDestroy(aFileName8);
	                    CleanupStack::PopAndDestroy(buf2);

	                    iWapiCompletionStatus = eap_status_allocation_error;
                        EAP_TRACE_DEBUG_SYMBIAN(
                                (_L("wapi_am_core_symbian_c::ImportFilesL: iWapiCompletionStatus != eap_status_ok")));  
                        if (in_imported_certificate_data != NULL)
                            delete in_imported_certificate_data;
                        if (in_imported_certificate_file_name != NULL)
                            delete in_imported_certificate_file_name;
                        return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);
					    
					    }

					iWapiCompletionStatus = in_imported_certificate_file_name->set_copy_of_buffer(aFileNamePtr8.Ptr(), aFileNamePtr8.Size());
					
                    CleanupStack::PopAndDestroy(aReadData);

					EAP_TRACE_DEBUG_SYMBIAN(
							(_L("wapi_am_core_symbian_c::ImportFilesL: Complete operation")));	
					
                    delete aFiles;
                    aFiles = NULL;

                    CleanupStack::PopAndDestroy(aPath8);
                    CleanupStack::PopAndDestroy(aPath);
                    CleanupStack::PopAndDestroy(aFileName8);
                    CleanupStack::PopAndDestroy(buf2);

                    if (iWapiCompletionStatus != eap_status_ok)
						{
	                    EAP_TRACE_DEBUG_SYMBIAN(
	                            (_L("wapi_am_core_symbian_c::ImportFilesL: iWapiCompletionStatus != eap_status_ok")));  
						if (in_imported_certificate_data != NULL)
							delete in_imported_certificate_data;
						if (in_imported_certificate_file_name != NULL)
							delete in_imported_certificate_file_name;
 						return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);
						}
					else
						{
                        EAP_TRACE_DEBUG_SYMBIAN(
                                (_L("wapi_am_core_symbian_c::ImportFilesL: iWapiCompletionStatus == eap_status_ok")));  
						iWapiCompletionStatus = iCertStorePartner->add_imported_certificate_file(
							in_imported_certificate_data,
							in_imported_certificate_file_name);
                        EAP_TRACE_DEBUG_SYMBIAN(
                                (_L("wapi_am_core_symbian_c::ImportFilesL: iCertStorePartner->add_imported_certificate_file == %d"), iWapiCompletionStatus));  
                         if (iWapiCompletionStatus != eap_status_ok && iWapiCompletionStatus != eap_status_pending_request)
                             {
                             TBuf8<KMaxFileName> aFile;
                             aFile.Copy(in_imported_certificate_file_name->get_data(in_imported_certificate_file_name->get_data_length()), in_imported_certificate_file_name->get_data_length());
                             iImportedFilenames.Append(aFile);
                             iWapiCompletionStatus = set_timer(
                                      this,
                                      EWapiAddCertificateFileTimerId, 
                                      0,
                                      0);
                            }
                        return EAP_STATUS_RETURN(iAmTools, iWapiCompletionStatus);	
						}
					}
				}
			else
				{
				aBadFile = true;
				}
			}
	
    delete aFiles;

    CleanupStack::PopAndDestroy(aPath8);
    CleanupStack::PopAndDestroy(aPath);
    CleanupStack::PopAndDestroy(aFileName8);
    CleanupStack::PopAndDestroy(buf2);
	EAP_TRACE_DEBUG_SYMBIAN(
		(_L("wapi_am_core_symbian_c::ImportFilesL: Operation failed or Complete")));	

	
	if(iWapiCompletionStatus != eap_status_pending_request || aFileFound == EFalse)
		{
			
		if(aBadFile == true || aDirectoryEmpty == true ||  aDirectoryExists == false)   	
				{
				if (m_is_client)
				    iWapiCompletionStatus = eap_status_file_does_not_exist;
				else
				    iWapiCompletionStatus = eap_status_ok;
				iCertStorePartner->complete_initialize_certificate_store( iCompletionOperation );
				}
			else
				{
				iWapiCompletionStatus = eap_status_ok;
				iCertStorePartner->complete_initialize_certificate_store( iCompletionOperation );
				}
		}
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::ImportFilesL() OUT\n" ) ) );
	return iWapiCompletionStatus;
	
	} // wapi_am_core_symbian_c::ImportFilesL()

// ---------------------------------------------------------
// wapi_am_core_symbian_c::CheckFilenameL()
// ---------------------------------------------------------
//
TBool wapi_am_core_symbian_c::CheckFilenameL(TPtr8 aFileNamePtr )
    {
    EAP_TRACE_DEBUG(iAmTools, 
            TRACE_FLAGS_DEFAULT, (
            EAPL("CheckFilenameL - Start\n")));

    TBool aFound = EFalse;
//    TBool aSaved = EFalse;
    
    RDbNamedDatabase& db = iCertificateStoreDb->GetCertificateStoreDb();
    
    // Create a buffer for the ascii strings - initialised in query
    HBufC8* asciibuf = HBufC8::NewLC(KMaxFileName);
    TPtr8 asciiString = asciibuf->Des();
    asciiString.Zero();
    
    // Buffer for unicode parameter
    HBufC* unicodebuf = HBufC::NewLC(KMaxFileName);
    TPtr unicodeString = unicodebuf->Des();
    
    HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
    TPtr sqlStatement = buf->Des();

    _LIT(KSQLQueryRow, "SELECT * FROM %S");
    sqlStatement.Format(KSQLQueryRow, &KCsWapiCertFileTable);

    EAP_TRACE_DATA_DEBUG_SYMBIAN( (
    "wapi_am_core_symbian_c::CheckFilenameL() sqlStatement for KCsWapiCertFileTable",
    sqlStatement.Ptr(), 
    sqlStatement.Size() ) );    
  
    TInt aFileCountInDB = 0;
    RDbView view;
    User::LeaveIfError(view.Prepare( db, TDbQuery(sqlStatement), TDbWindow::EUnlimited, RDbView::EUpdatable));
    
    CleanupClosePushL(view);
    User::LeaveIfError(view.EvaluateAll()); 
    if (view.FirstL())
        {
        do
            {
            view.GetL();        
            switch (view.ColType(KDefaultColumnNumberOne))
                {
                case EDbColText:                
                    {
                    unicodeString = view.ColDes(KDefaultColumnNumberOne);
                    // Convert to 8-bit
                                                
                    if (unicodeString.Size() > 0)
                        {
                        asciiString.Copy(unicodeString);
                        if (aFileNamePtr.Compare(asciiString) == 0)
                            {
                                 aFound = ETrue;
                            }
                         } 
                    else 
                        {
                        // Empty field. Do nothing
                        break;
                        }
                    }
                break;
                case EDbColBinary:
                    {
                    TPtrC8 dbValuePtrC8 = view.ColDes8( KDefaultColumnNumberOne );
                      
                    asciiString.Copy( dbValuePtrC8 );
                    
                    if (asciiString.Size()>0 && aFileCountInDB<3)
                        {
                        if (aFileNamePtr.Compare(asciiString) == 0)
                            {
                                aFound = ETrue;
                            }
                        EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                                "wapi_am_core_symbian_c::CheckFilenameL() BINARY value from DB",
                                asciiString.Ptr(), asciiString.Size() ) );
                        }
                    }
                break;
               
                default:
                    {
                    EAP_TRACE_DEBUG(
                            iAmTools,
                            TRACE_FLAGS_DEFAULT,
                            (EAPL("wapi_am_core_symbian_c::CheckFilenameL: Unexpected column type. %s\n"), asciiString.Ptr(), asciiString.Size() )); 
                    }
                    break;
                }
            } while (view.NextL() != EFalse);
    
    
    
        }
    
    CleanupStack::PopAndDestroy(4); //  asciibuf, unicodebuf, buf, view
    
    EAP_TRACE_DEBUG(iAmTools, 
            TRACE_FLAGS_DEFAULT, (
            EAPL("CheckFilenameL - Out\n")));
    return aFound;
   }
                
// ---------------------------------------------------------
// wapi_am_core_symbian_c::UpdatePasswordTimeL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::UpdatePasswordTimeL()
	{

	} // wapi_am_core_symbian_c::UpdatePasswordTimeL()

// ---------------------------------------------------------
// wapi_am_core_symbian_c::CheckPasswordTimeValidityL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::CheckPasswordTimeValidityL()
	{
	/* Check validity of password against timelimit */
	
	EAP_TRACE_DEBUG(iAmTools, 
			TRACE_FLAGS_DEFAULT, (
			EAPL("CheckPasswordTimeValidityL - Start\n")));

	} // wapi_am_core_symbian_c::CheckPasswordTimeValidityL()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC(const TDesC8& aInBuf8,
        HBufC16** aOutBuf16)
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                            "wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC() IN\n" ) ) );

    // convert utf8->unicode,
    // aInBuf8 is UTF8 string, unicode max length is
    // then the length of UTF8 string.
    // NOTE, HBufC16 length means count of 16-bit objects.
    *aOutBuf16 = HBufC16::NewL(aInBuf8.Size() );
    CleanupStack::PushL(aOutBuf16);
    TPtr16 outBufPtr16 = ( *aOutBuf16 )->Des();

    const TPtrC8 inBufPtrC8(aInBuf8);

    CnvUtfConverter::ConvertToUnicodeFromUtf8(outBufPtr16, inBufPtrC8);

    // print data
    EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                            "wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC() aInBuf8" ),
                    inBufPtrC8.Ptr(), inBufPtrC8.Size() ) );

    EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                            "wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC() aOutBuf16" ),
                    outBufPtr16.Ptr(), outBufPtr16.Size() ) );

     EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                            "wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC() OUT\n" ) ) );

    } // wapi_am_core_symbian_c::ConvertFromBuf8ToBuf16LC()

// ---------------------------------------------------------
// wapi_am_core_symbian_c::ReadIntDbValue()
// ---------------------------------------------------------
//
TInt64 wapi_am_core_symbian_c::ReadIntDbValueL(
	RDbNamedDatabase& aDb,
	const TDesC& aColumnName,
	const TDesC& aSqlStatement )
    {
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
			EAPL( "wapi_am_core_symbian_c::ReadIntDbValueL()\n" ) ) );
    TPtrC columnName;    
	columnName.Set( aColumnName );
	
	RDbView view;

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
		EAPL( "ReadIntDbValue() prepare view\n" ) ) );

	User::LeaveIfError( view.Prepare( aDb, TDbQuery(
		aSqlStatement ) ) );
	CleanupClosePushL( view );
	
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, (
		EAPL("ReadIntDbValue() evaluate view\n" ) ) );
	User::LeaveIfError( view.EvaluateAll() );		
	// Get the first (and only) row
	view.FirstL();
	view.GetL();
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL( colSet );
	TInt64 retVal = view.ColInt64( colSet->ColNo( columnName ) );

	CleanupStack::PopAndDestroy( colSet ); 
	CleanupStack::PopAndDestroy( &view );

	return retVal;
    } // wapi_am_core_symbian_c::ReadIntDbValueL


// ================= New, complete asynch. query methods in active object =======================


// ---------------------------------------------------------
// wapi_am_core_symbian_c::CompleteHandlingDeviceSeedQueryState()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::CompleteHandlingDeviceSeedQueryState()
	{
	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"wapi_am_core_symbian_c::CompleteHandlingDeviceSeedQueryState() IN\n" ) ) );
	
	if ( iStatus != KErrNone )
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
			"ERROR: wapi_am_core_symbian_c::CompleteHandlingDeviceSeedQueryState() \
			aStatus=%d.\n" ), iStatus.Int() ) );
		}
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"Manufacturer" ), iDeviceId.iManufacturer.Ptr(),
		iDeviceId.iManufacturer.Size() ) );
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"Model"), iDeviceId.iModel.Ptr(), iDeviceId.iModel.Size() ) );
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"Revision"), iDeviceId.iRevision.Ptr(), iDeviceId.iRevision.Size()));
	EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		"SerialNumber"), iDeviceId.iSerialNumber.Ptr(),
		iDeviceId.iSerialNumber.Size() ) );
		
	// Combine all needed items.			
	TBuf<KMaxDeviceSeedLength> deviceSeed16;	
	deviceSeed16 += iDeviceId.iManufacturer;
	deviceSeed16 += iDeviceId.iModel;
	deviceSeed16 += iDeviceId.iSerialNumber;
		
	TBuf8<KMaxDeviceSeedSize> deviceSeed8;
	deviceSeed8.Copy(deviceSeed16);		

	if ( iWapiDeviceSeed != NULL )
		{
		if( deviceSeed8.Size() > 0)
		    {
		    iWapiDeviceSeed->set_copy_of_buffer(
			    deviceSeed8.Ptr(),
				deviceSeed8.Size());
			}
		}
	TRAPD(err, DisconnectMMETEL());
 	if (err)
		{
		EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
		        "ERROR: wapi_am_core_symbian_c::Leave from DisconnectMMETEL () err=%d.\n" ), err ) );
		}
	
 	iWapiCompletionStatus = set_timer(
			this,
			EWapiAddCertificateFileTimerId, 
			0,
			0);

	EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	    "wapi_am_core_symbian_c::CompleteHandlingDeviceSeedQueryState() OUT\n" ) ) );
	
	}


// ---------------------------------------------------------
// wapi_am_core_symbian_c::CopyBufToEapVarL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::CopyBufToEapVarL(
	const TDesC8& aInBuf, eap_variable_data_c& aOutEapVar )
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::CopyBufToEapVar() \
         buf size=%d.\n" ), aInBuf.Size() ) );
	
    iWapiCompletionStatus = eap_status_ok;
    
	if ( aInBuf.Size() > 0 )
		{
		iWapiCompletionStatus = aOutEapVar.set_copy_of_buffer(
		    aInBuf.Ptr(), aInBuf.Size() );
		}
	else
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
            "ERROR: wapi_am_core_symbian_c::CopyBufToEapVar() \
            No data to copy!\n" ) ) );
	    aOutEapVar.reset();
	    return;
		}
	
	if ( iWapiCompletionStatus != eap_status_ok )
		{
	    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
	        "ERROR: wapi_am_core_symbian_c::CopyBufToEapVar() \
	        Failed to copy data, status=%d\n" ), iWapiCompletionStatus ) );
		User::Leave( iAmTools->convert_eapol_error_to_am_error(
		iWapiCompletionStatus ) );
		}
	
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "wapi_am_core_symbian_c::CopyBufToEapVar() OUT\n" ) ) );

    } // wapi_am_core_symbian_c::CopyBufToEapVar()


// ---------------------------------------------------------
// wapi_am_core_symbian_c::complete_start_certificate_import()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::complete_start_certificate_import()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_start_certificate_import()" ) ) );
    // Now that the certificate import was done, the list of available
    // certificates can be queried.
    // This functionality is completed with complete_query_certificate_list
    
    iWapiCompletionStatus = iCertStorePartner->query_certificate_list();
    
    return iWapiCompletionStatus;
    
    }

// ---------------------------------------------------------
// wapi_am_core_symbian_c::complete_query_certificate_list()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::complete_query_certificate_list(
    EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const ca_certificates,
    EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const user_certificates)
    {

    // Call the actual complete_query function with the implementation
    TInt trapErr = KErrNone;
    eap_status_e returnErr = eap_status_ok;
    TRAP( trapErr, returnErr = complete_query_certificate_listL(ca_certificates, user_certificates ));
    
    // There was some allocation error in the trapped function
    if ( trapErr != KErrNone )
        {
        return EAP_STATUS_RETURN( iAmTools, eap_status_allocation_error);
        }
    
    return EAP_STATUS_RETURN( iAmTools, returnErr );
    }

// ---------------------------------------------------------
// wapi_am_core_symbian_c::complete_query_certificate_list()
// ---------------------------------------------------------
//
eap_status_e wapi_am_core_symbian_c::complete_query_certificate_listL(
    EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const ca_certificates,
    EAP_TEMPLATE_CONST eap_array_c<eap_variable_data_c> * const user_certificates)
    {
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_query_certificate_list() start" ) ) );
    
     TInt memIndex = 0;
    eap_status_e status = eap_status_ok;
    _LIT(KNone, "None");
    _LIT8(KNone8, "None");

    wapi_asn1_der_parser_c wapiAsn1(iAmTools);
    if ( wapiAsn1.get_is_valid() == false )
        {
        EAP_TRACE_END(iAmTools, TRACE_FLAGS_DEFAULT);
        return EAP_STATUS_RETURN(iAmTools, eap_status_allocation_error);
        }

    eap_variable_data_c subjectName(iAmTools);
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_query_certificate_list() loops" ) ) );
    // If there are CA labels, then we store them to the member variable
    if ( ca_certificates != NULL )
        {
        if ( ca_certificates->get_object_count() > 0 )
            {
            // Create the array since data exists
            *iCACerts = new(ELeave) RArray<TBuf<KCsMaxWapiCertLabelLen> >;
            CleanupStack::PushL(*iCACerts);
             memIndex++;
            ( *iCACerts )->Reset();

            *iCACertsData = new(ELeave) RArray<TBuf8<KMaxIdentityLength> >;
            CleanupStack::PushL(*iCACertsData);
             memIndex++;
           
            ( *iCACertsData )->Reset();

            // Copy "none" as the first item into the array, requested by UI
            HBufC* tmp = HBufC::NewLC( 4 );
            HBufC8* tmpData = HBufC8::NewLC( 4 );
            memIndex++;
            memIndex++;
            *tmp = KNone;
            *tmpData = KNone8;
            
            EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                     "wapi_am_core_symbian_c::complete_query_certificate_list() add CA empty" ) ) );
            ( *iCACerts )->AppendL( *tmp );
            ( *iCACertsData )->AppendL( *tmpData );
            
            // Loop all the given identities through
            for ( TInt i = 0; i < ca_certificates->get_object_count(); i++ )
                {
                EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                         "wapi_am_core_symbian_c::complete_query_certificate_list() loop CA" ) ) );
                // Decode and store data to the RArray 
                if (ca_certificates->get_object(i) != NULL)
                    {
                    status = wapiAsn1.get_decoded_subject_name(
                            ca_certificates->get_object(i), &subjectName );
                    // Don't store label if an error occurred
                    if ( status != eap_status_ok )
                        {
                        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                                 "wapi_am_core_symbian_c::complete_query_certificate_list() decode fail" ) ) );
                        }
                    else
                        {
                        TBuf8<KCsMaxWapiCertLabelLen> tmpLabel;
                        tmpLabel.Append( subjectName.get_data( subjectName.get_data_length() ),
                                         subjectName.get_data_length() );
                        HBufC16* tmp16Label;
                        ConvertFromBuf8ToBuf16LC( tmpLabel, &tmp16Label );
                        memIndex++;
                       (*iCACerts)->AppendL( *tmp16Label );
          
                        HBufC8* tmpData = HBufC8::NewLC( ca_certificates->get_object(i)->get_data_length() );
                        memIndex++;
                        TPtr8 tmpDataPtr = tmpData->Des();
                               
                        tmpDataPtr.Copy(ca_certificates->get_object(i)->get_data(), ca_certificates->get_object(i)->get_data_length());
     
                        ( *iCACertsData )->AppendL( *tmpData );
    
                        EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                            "wapi_am_core_symbian_c::complete_query_certificate_list() CA identity",
                            tmpDataPtr.Ptr(), 
                            tmpDataPtr.Size() ) );    
                       }
                    
                    subjectName.reset();
                    }
                }
            }
        }

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_query_certificate_list() looped CA continue with Client" ) ) );
    
    // If there are labels, then we store them to the member variable
    if ( user_certificates != NULL )
        {
        if ( user_certificates->get_object_count() > 0 )
            {
            // Create the array since data exists
            *iUserCerts = new(ELeave) RArray<TBuf<KCsMaxWapiCertLabelLen> >;
            CleanupStack::PushL(*iUserCerts);
            memIndex++;
            ( *iUserCerts )->Reset();

            *iUserCertsData = new(ELeave) RArray<TBuf8<KMaxIdentityLength> >;
            CleanupStack::PushL(*iUserCertsData);
             memIndex++;
            ( *iUserCertsData )->Reset();

            // Copy "none" as the first item into the array, requested by UI
            HBufC* tmp = HBufC::NewLC( 4 );
            HBufC8* tmpData = HBufC8::NewLC( 4 );
            memIndex++;
            memIndex++;
            *tmp = KNone;
            *tmpData = KNone8;
            
            ( *iUserCerts )->AppendL( *tmp );
            ( *iUserCertsData )->AppendL( *tmpData );
            
            // Loop all the given identities through
            for ( TInt i = 0; i < user_certificates->get_object_count(); i++ )
                {
                EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                         "wapi_am_core_symbian_c::complete_query_certificate_list() loop user" ) ) );
                // Decode and store data to the RArray
                if (user_certificates->get_object(i) != NULL)
                    {
                    status = wapiAsn1.get_decoded_subject_name(
                            user_certificates->get_object(i), &subjectName );
                    // Don't store label if an error occurred
                    if (status != eap_status_ok)
                        {
                        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                                 "wapi_am_core_symbian_c::complete_query_certificate_list() decode fail" ) ) );
                        }
                    else
                        {
                        TBuf8<KCsMaxWapiCertLabelLen> tmpLabel;
                        tmpLabel.Append( subjectName.get_data( subjectName.get_data_length() ),
                                         subjectName.get_data_length() );
                        HBufC16* tmp16Label;
                        ConvertFromBuf8ToBuf16LC( tmpLabel, &tmp16Label );
                        memIndex++;
                        ( *iUserCerts )->AppendL( *tmp16Label );
                        
                        HBufC8* tmpData = HBufC8::NewLC( user_certificates->get_object(i)->get_data_length() );
                        memIndex++;
                        TPtr8 tmpDataPtr = tmpData->Des();
                               
                        tmpDataPtr.Copy(user_certificates->get_object(i)->get_data(), user_certificates->get_object(i)->get_data_length());
        
                        ( *iUserCertsData )->AppendL( *tmpData);
                         
                        
                        EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                             "wapi_am_core_symbian_c::complete_query_certificate_list() client identity",
                             tmpDataPtr.Ptr(), 
                             tmpDataPtr.Size() ) ); 
                         }
                    subjectName.reset();
                    }
                }
            }
        }
    if (*iCACerts)
        {
        for (TInt aCa = 0; aCa <(*iCACerts)->Count(); aCa++)
            {
            TPtrC certPtr;
            certPtr.Set ((**iCACerts)[aCa]);
            EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CaCert:"), certPtr.Ptr(),
                certPtr.Size() ));
    
            EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                "wapi_am_core_symbian_c::complete_query_certificate_list() CA identity",
                (**iCACertsData )[aCa].Ptr(), 
                (**iCACertsData )[aCa].Size() ) ); 
    
            }
        }
    if (*iUserCerts)
        {
        for (TInt aCa = 0; aCa <(*iUserCerts)->Count(); aCa++)
            {
            TPtrC certPtr;
            certPtr.Set ((**iUserCerts)[aCa]);
            EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "ClientCert:"), certPtr.Ptr(),
                certPtr.Size() ));
    
            EAP_TRACE_DATA_DEBUG_SYMBIAN( (
                 "wapi_am_core_symbian_c::complete_query_certificate_list() client identity",
                 (**iUserCertsData )[aCa].Ptr(), 
                 (**iUserCertsData )[aCa].Size() ) ); 
            }
        }

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_query_certificate_list() looping done" ) ) );

    // The memory handling is up to the caller. The pointers to the arrays are set to NULL
    // and the caller will handle the data and the memory hanling from now on
    if (memIndex != 0)
        {
        CleanupStack::Pop(memIndex);
        }

    // if the status is failed, then we don't send any lists to the caller,
    // delete the lists
    if (status != eap_status_ok)
        {
        delete *iUserCerts;
        delete *iCACerts;
        delete *iUserCertsData;
        delete *iCACertsData;
        *iUserCerts = NULL;
        *iCACerts = NULL;
        *iUserCertsData = NULL;
        *iCACertsData = NULL;
        }
    iUserCerts = NULL;
    iCACerts = NULL;
    iUserCertsData = NULL;
    iCACertsData = NULL;

    // Now the wapicertificates function can continue from its getAllCertificates
    // function
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_query_certificate_list(), labels ready" ) ) );
    TRequestStatus* reqStatus = iWapiCertsStatus;
    User::RequestComplete(reqStatus, KErrNone);

    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::complete_query_certificate_list- end" )));

    return status;
    }


// ---------------------------------------------------------
// wapi_am_core_symbian_c::GetAllCertificateLabelsL()
// ---------------------------------------------------------
//
void wapi_am_core_symbian_c::GetAllCertificateLabelsL( RArray<TBuf<KCsMaxWapiCertLabelLen> > **aUserCerts,
        RArray<TBuf<KCsMaxWapiCertLabelLen> > **aCACerts,
        RArray<TBuf8<KMaxIdentityLength> > **aUserCertsData,
        RArray<TBuf8<KMaxIdentityLength> > **aCACertsData,
        TRequestStatus& aStatus)

    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::GetAllCertificateLabelsL() start" ) ) );
    
    // Check that the received pointers are valid

    if ( aUserCerts == NULL || aCACerts == NULL || aUserCertsData == NULL || aCACertsData == NULL )
        {
        User::Leave( KErrArgument );
        }
    
    // Set the WAPICertificates Active object status to pending
    iWapiCertsStatus = &aStatus;
    *iWapiCertsStatus = KRequestPending;
    
    eap_status_e status = eap_status_ok;
    
    if ( iCertStorePartner == NULL )
        {
        EAP_TRACE_ERROR(
            iAmTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("ERROR: wapi_am_core_symbian_c::GetAllCertificateLabelsL \
                    certStoreparner is NULL!\n"))); 
        User::Leave( KErrGeneral );
        }
    
    // Start certificate import and continue with certificate list query only if everything goes ok
    status = iCertStorePartner->start_certificate_import();
    if (status != eap_status_pending_request)
        {  
        EAP_TRACE_ERROR(
            iAmTools,
            TRACE_FLAGS_DEFAULT,
            (EAPL("ERROR: wapi_am_core_symbian_c::GetAllCertificateLabelsL\
                    configure failed!\n")));
        User::Leave(iAmTools->convert_eapol_error_to_am_error(EAP_STATUS_RETURN(iAmTools, status)));
        } 
        
    // store the given pointers to member variables to be able to update
    // the lists when the operation is completed
    iUserCerts = aUserCerts;
    iCACerts = aCACerts;
    iUserCertsData = aUserCertsData;
    iCACertsData = aCACertsData;
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
             "wapi_am_core_symbian_c::GetAllCertificateLabelsL() end" ) ) );
    }
    
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

EAP_FUNC_EXPORT wapi_am_base_core_c *wapi_am_base_core_c::new_wapi_am_core(
		abs_eap_am_tools_c * const tools,
		abs_wapi_am_core_c * const partner,
		const bool is_client_when_true,
		const eap_am_network_id_c* eap_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("WAPI_Core: wapi_am_core_symbian_c::wapi_am_base_core_c():\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: wapi_am_base_core_c::wapi_am_base_core_c()");

	wapi_am_core_symbian_c * wapi_am_core_symbian = 0;
#if defined(WAPI_USE_CERTIFICATE_STORE)

	TRAPD( err, wapi_am_core_symbian = wapi_am_core_symbian_c::NewL(
		tools,
		partner,
		is_client_when_true));

	if (err || wapi_am_core_symbian == 0)
	{
		return 0;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return wapi_am_core_symbian;

#else

	return 0;

#endif //#if defined(WAPI_USE_CERTIFICATE_STORE)

}


//--------------------------------------------------	

// End of file
