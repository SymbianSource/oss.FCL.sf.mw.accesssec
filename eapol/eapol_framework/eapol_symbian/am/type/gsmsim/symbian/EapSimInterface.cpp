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
* %version: 21 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 195 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include "EapSimInterface.h"
#include "eap_automatic_variable.h"

#include <mmtsy_names.h>
#include "eap_sim_triplets.h" // For SIM_SRES_LENGTH.


// ================= MEMBER FUNCTIONS =======================

CEapSimIsaInterface::CEapSimIsaInterface(abs_eap_am_tools_c* const aTools, eap_am_type_gsmsim_symbian_c* const aParent)
: CActive(CActive::EPriorityStandard)
, iParent(aParent)
, m_am_tools(aTools)
, iAuthenticationData(NULL)
, iQueryId(EQueryNone)
, iMMETELConnectionStatus(EFalse)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::CEapSimIsaInterface()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::CEapSimIsaInterface()");
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapSimIsaInterface* CEapSimIsaInterface::NewL(abs_eap_am_tools_c* const aTools, 
											   eap_am_type_gsmsim_symbian_c* const aParent)
{
	CEapSimIsaInterface* self = new(ELeave) CEapSimIsaInterface(aTools, aParent);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

void CEapSimIsaInterface::ConstructL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	CActiveScheduler::Add(this);	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapSimIsaInterface::~CEapSimIsaInterface()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::~CEapSimIsaInterface()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::~CEapSimIsaInterface()");

	if(IsActive())
	{
		Cancel();
	}
	
	DisconnectMMETel();

	delete iAuthenticationData;
	iAuthenticationData = NULL;
		
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapSimIsaInterface::QueryIMSIL()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::QueryIMSIL()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::QueryIMSIL()");

	iQueryId = EQueryIMSI;

	// Create MMETEl connection.
	User::LeaveIfError( CreateMMETelConnectionL() );
	
   	iPhone.GetSubscriberId( iStatus, iSubscriberId ); 
 	
	if( !IsActive() )
	{
		SetActive();
	}  

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapSimIsaInterface::QueryKcAndSRESL(const TDesC8& aRand)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::QueryKcAndSRESL()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::QueryKcAndSRESL()");

	iQueryId = EQuerySRESandKC;

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("RAND"),
			aRand.Ptr(),
			aRand.Size()));

	// Rand must be 16 bytes
	if (static_cast<u16_t>(aRand.Length()) != SIM_RAND_LENGTH)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ISA interface: Illegal RAND - Incorrect length.\n")));
		User::Leave(KErrArgument);
	}
	
	// Create MMETEL connection.
	User::LeaveIfError( CreateMMETelConnectionL() );
	
	// Open CustomAPI.
	User::LeaveIfError( iCustomAPI.Open(iPhone) );		
	
	iEAPSim.iRandomParameters.Copy( aRand ); //Copy the rand to iEAPSim

	//Pack iEAPSim to iAuthenticationData for passing it to the custom API.
	iAuthenticationData = new (ELeave) RMmCustomAPI::TSimDataPckg( iEAPSim );
	
    iCustomAPI.GetWlanSimAuthenticationData( iStatus, *iAuthenticationData );	
	
	if( !IsActive() )
	{
		SetActive();
	}  

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
 
void CEapSimIsaInterface::DoCancel()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::DoCancel(): iQueryId=%d\n"),
		iQueryId) );
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::DoCancel()");

	if (iQueryId == EQuerySRESandKC)
	{
		iQueryId = EQueryNone;

		// Cancel the request.
		iCustomAPI.CancelAsyncRequest( ECustomGetSimAuthenticationDataIPC );

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::DoCancel(): CANCELLED CUSTOM API REQUEST\n") ) );
	}
}

//--------------------------------------------------

void CEapSimIsaInterface::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::RunL(). iStatus.Int()=%d, iQueryId=%d\n"),
		iStatus.Int(),
		iQueryId));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::RunL()");

	TInt error = KErrNone;
	eap_variable_data_c imsi(m_am_tools); // Keeping it here to avoid "error" in ARMV5 build.
	
	// This is to store the IMSI, which is in Unicode form.
	eap_variable_data_c imsiInUnicode(m_am_tools); // Keeping it here to avoid "error" in ARMV5 build.
	
	// Keeping it here to remove compiler warning.
	eap_status_e completion_status(eap_status_ok);
	
	if (iStatus.Int() == KErrNone)
	{	
		switch( iQueryId )
		{
			case EQueryIMSI:
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ISA interface: Got IMSI reply.\n")));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IMSI"),
						iSubscriberId.Ptr(),
						iSubscriberId.Size()));

				iQueryId = EQueryNone;

				// Convert the IMSI from unicode to UTF8 characters.

				completion_status = imsiInUnicode.set_buffer(iSubscriberId.Ptr(), iSubscriberId.Size(), false, false);

				if (completion_status != eap_status_ok)
				{
					imsiInUnicode.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ISA interface: Could not set buffer for IMSI. Not proceeding further here.\n")));
				}
				else
				{				
					completion_status = m_am_tools->convert_unicode_to_utf8(imsi, imsiInUnicode);
					
					if (completion_status != eap_status_ok)
					{
						imsi.reset();
						EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ISA interface: Could not convert IMSI from UNICODE to UTF8. Not proceeding further here.\n")));
					}
				}

				DisconnectMMETel();

				TRAP(error, iParent->complete_SIM_imsi_L(&imsi, completion_status));
			
			break;
			
			case EQuerySRESandKC:
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####ISA interface: Got KC and SRES reply. ####\n")));			
				
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SRES before trimming"),
						iEAPSim.iSRES.Ptr(),
						iEAPSim.iSRES.Size()));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("KC"),
						iEAPSim.iKC.Ptr(),
						iEAPSim.iKC.Size()));
						
				iQueryId = EQueryNone;

				// Trim the length of SRES -  Remove once the correct length is set for SRES, may be by the API or some where else.
				iEAPSim.iSRES.SetLength(SIM_SRES_LENGTH);
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SRES after Trimming"),
						iEAPSim.iSRES.Ptr(),
						iEAPSim.iSRES.Size()));				
								
				delete iAuthenticationData;
				iAuthenticationData = NULL;
							
				DisconnectMMETel();

				// Complete
				TRAP(error, iParent->complete_SIM_kc_and_sres_L(iEAPSim.iKC, iEAPSim.iSRES, completion_status));			
			
			break;
		}
	} 
	else 
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ISA interface: Got error reply.\n")));
		
		if( EQuerySRESandKC == iQueryId )
		{
			iQueryId = EQueryNone;

			DisconnectMMETel();
			
			// Handle duplicate RAND values.
			// If duplicate RAND values are being used, we get KErrArgument here.
			if(iStatus.Int() == KErrArgument)
			{
				completion_status = eap_status_not_fresh_challenges;
			}
			else
			{
				// For all other errors.
				completion_status = m_am_tools->convert_am_error_to_eapol_error(iStatus.Int());
			}
			
			// Complete the request.
			TRAP(error, iParent->complete_SIM_kc_and_sres_L(iEAPSim.iKC, iEAPSim.iSRES, completion_status));							
		}
		else if(EQueryIMSI == iQueryId)
		{
			completion_status = m_am_tools->convert_am_error_to_eapol_error(iStatus.Int());
			
			iQueryId = EQueryNone;

			DisconnectMMETel();

			TRAP(error, iParent->complete_SIM_imsi_L(&imsi, completion_status));
		}
	}	

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

TInt CEapSimIsaInterface::CreateMMETelConnectionL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::CreateMMETelConnectionL()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::CreateMMETelConnectionL()");

	TInt errorCode = KErrNone;
	
	// MMETel need to be connected only once.    
    if( !iMMETELConnectionStatus )
    {
		RTelServer::TPhoneInfo phoneInfo;
		TInt phoneCount = 0;

		// Connect to ETel server
		User::LeaveIfError( iServer.Connect() ); 	
		
	    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Connected to ETel server.\n")));	

		//This function loads an ETel TSY module. mmtsy.
		errorCode = iServer.LoadPhoneModule( KMmTsyModuleName );	
		
	    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Loaded phone module.\n")));	    
		
		if ( errorCode != KErrNone && errorCode != KErrAlreadyExists )
		{
			User::Leave( errorCode );
		}

		iServer.SetExtendedErrorGranularity( RTelServer::EErrorExtended );

		//This function retrieves the total number of phones supported by all 
		//the currently loaded ETel (TSY) modules.
		User::LeaveIfError( iServer.EnumeratePhones( phoneCount ) );	
		
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Number of phones supported by the loaded ETel = %d.\n"), phoneCount));
		
		// This function retrieves information associated with the specified phone
		while ( ( phoneCount-- ) && ( phoneInfo.iName != KMmTsyPhoneName ) ) 
		{ 
			User::LeaveIfError( iServer.GetPhoneInfo( phoneCount, phoneInfo ) );		
			
		    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Got phone info.\n")));
		} 

		// This function opens a phone subsession by name, 
		User::LeaveIfError( iPhone.Open( iServer, phoneInfo.iName ) );	
		
	    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Opened phone subsession.\n")));
		
		// MMETel connected and the phone module loaded fine.	
		iMMETELConnectionStatus = ETrue; 	
    }
    else
    {
    	// MMETel already connected.
	    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("MMETel connected once already.\n")));
    }
	    
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
    
    return errorCode;	
}

void CEapSimIsaInterface::DisconnectMMETel()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapSimIsaInterface::DisconnectMMETel()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapSimIsaInterface::DisconnectMMETel()");

	iQueryId = EQueryNone;

	// Close the custom API since we don't need it any more.
	iCustomAPI.Close();

    if( iMMETELConnectionStatus )
    {
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Closing RMobilePhone and MMETEL.\n")));
		
		iPhone.Close();
		iServer.Close(); // Phone module is unloaded automatically when RTelServer session is closed
		
		iMMETELConnectionStatus = EFalse;
    }
    else
    {
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("RMobilePhone and MMETEL already closed.\n")));    	
    }	
}


// End of file
