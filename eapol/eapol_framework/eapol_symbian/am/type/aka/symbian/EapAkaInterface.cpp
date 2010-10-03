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
* %version: 19 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 603 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

// INCLUDE FILES
#include "EapAkaInterface.h"
#include "eap_type_aka_types.h"
#include "eap_automatic_variable.h"

#include <mmtsy_names.h>
#include <etelmmerr.h>

// ================= MEMBER FUNCTIONS =======================

CEapAkaInterface::CEapAkaInterface(abs_eap_am_tools_c* const aTools, eap_am_type_aka_symbian_c* const aParent)
: CActive(CActive::EPriorityStandard)
, iParent(aParent)
, m_am_tools(aTools)
, iAuthenticationData(NULL)
, iQueryId(EQueryNone)
, iMMETELConnectionStatus(EFalse)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::CEapAkaInterface\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::CEapAkaInterface()");
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapAkaInterface* CEapAkaInterface::NewL(abs_eap_am_tools_c* const aTools, 
											   eap_am_type_aka_symbian_c* const aParent)
{
	CEapAkaInterface* self = new(ELeave) CEapAkaInterface(aTools, aParent);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

void CEapAkaInterface::ConstructL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	CActiveScheduler::Add(this);	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapAkaInterface::~CEapAkaInterface()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::~CEapAkaInterface\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::~CEapAkaInterface()");

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

void CEapAkaInterface::QueryIMSIL()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: CEapAkaInterface::QueryIMSIL()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::QueryIMSIL()");

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

void CEapAkaInterface::QueryRESL( eap_variable_data_c * const aRand, eap_variable_data_c * const aAUTN )
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: CEapAkaInterface::QueryRESL(), CK, IK and AUTS.\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::QueryRESL()");

	iQueryId = EQueryRES;

	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("RAND"),
			aRand->get_data(aRand->get_data_length()),
			aRand->get_data_length()));
			
	EAP_TRACE_DATA_DEBUG( m_am_tools, TRACE_FLAGS_DEFAULT,(EAPL("AUTN"),
			aAUTN->get_data(aAUTN->get_data_length()),
			aAUTN->get_data_length()));
			
	// Rand must be 16 bytes
	if (static_cast<u16_t>( aRand->get_data_length() ) != EAP_TYPE_AKA_MINIMUM_RAND_LENGTH)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Illegal RAND - Incorrect length.\n")));
		User::Leave(KErrArgument);
	}

	// AUTN must be 16 bytes
	if (static_cast<u16_t>( aAUTN->get_data_length() ) != EAP_TYPE_AKA_MINIMUM_AUTN_LENGTH)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Illegal AUTN - Incorrect length.\n")));
		User::Leave(KErrArgument);
	}
	
	// Create MMETEL connection.
	User::LeaveIfError( CreateMMETelConnectionL() );
	
	// Open CustomAPI.
	User::LeaveIfError( iCustomAPI.Open(iPhone) );
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: OPENED CUSTOM API \n")));
	
	u8_t *rand = aRand->get_data(aRand->get_data_length());
	u8_t *autn = aAUTN->get_data(aAUTN->get_data_length());
	
	iEAPAka.iRandomParameters.Copy( rand, EAP_TYPE_AKA_MINIMUM_RAND_LENGTH); //Copy the rand to iEAPAka
	
	iEAPAka.iAUTN.Copy( autn, EAP_TYPE_AKA_MINIMUM_AUTN_LENGTH); //Copy the AUTN to iEAPAka

	//Pack iEAPAka to iAuthenticationData for passing it to the custom API.
	iAuthenticationData = new (ELeave) RMmCustomAPI::TAkaDataPckg( iEAPAka );
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Before querying CustomAPI GetWlanSimAuthenticationData \n")));
		
    iCustomAPI.GetWlanSimAuthenticationData( iStatus, *iAuthenticationData );	
    
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: After querying CustomAPI. iStatus.Int() =%d \n"), iStatus.Int() ));
    
	if( !IsActive() )
	{
		SetActive();
	}  

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
 
void CEapAkaInterface::DoCancel()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::DoCancel() - Cancelling MMETEL query, iQueryId=%d\n"),
		iQueryId) );
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::DoCancel()");

	if (iQueryId == EQueryRES)
	{
		iQueryId = EQueryNone;

		// Cancel the request.
		iCustomAPI.CancelAsyncRequest( ECustomGetSimAuthenticationDataIPC );

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::DoCancel(): CANCELLED CUSTOM API REQUEST \n")));
	}
}

//--------------------------------------------------

void CEapAkaInterface::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::RunL(). iStatus.Int()=%d, iQueryId=%d\n"),
		iStatus.Int(),
		iQueryId));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::RunL()");

	
	TInt error = KErrNone;
	eap_status_e completion_status = eap_status_ok;
	eap_status_e AuthenticationStatus = eap_status_ok;
	
	eap_variable_data_c imsi(m_am_tools); // Keeping it here to avoid "error" in ARMV5 build.
	
	// This is to store the IMSI, which is in Unicode form.
	eap_variable_data_c imsiInUnicode(m_am_tools); // Keeping it here to avoid "error" in ARMV5 build.
	
	eap_variable_data_c res(m_am_tools);
	eap_variable_data_c ck(m_am_tools);
	eap_variable_data_c ik(m_am_tools);
	eap_variable_data_c auts(m_am_tools);	
	
	if (iStatus.Int() == KErrNone)
	{	
		switch( iQueryId )
		{
			case EQueryIMSI:

				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Got IMSI reply.\n")));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IMSI"),
						iSubscriberId.Ptr(),
						iSubscriberId.Size()));
				
				iQueryId = EQueryNone;

				// Convert the IMSI from unicode to UTF8 characters.

				completion_status = imsiInUnicode.set_buffer(iSubscriberId.Ptr(), iSubscriberId.Size(), false, false);

				if (completion_status != eap_status_ok)
				{
					imsiInUnicode.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not set buffer for IMSI.\n")));
					
					// No need to continue. The request will be completed towards the end, in this kind of error situation.
					break;
				}
				
				completion_status = m_am_tools->convert_unicode_to_utf8(imsi, imsiInUnicode);
				
				if (completion_status != eap_status_ok)
				{
					imsi.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not convert IMSI from UNICODE to UTF8.\n")));
					break;					
				}
				
				// Complete. This happens only if completion_status is eap_status_ok so far.
				TRAP(error, iParent->complete_AKA_imsi_L(&imsi, completion_status));
			
			break;
			
			case EQueryRES:

				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("####AKA interface: Got RES, CK, IK and AUTS reply. ####\n")));			
				
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("RES"),
						iEAPAka.iRES.Ptr(),
						iEAPAka.iRES.Size()));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CK"),
						iEAPAka.iCK.Ptr(),
						iEAPAka.iCK.Size()));

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IK"),
						iEAPAka.iIK.Ptr(),
						iEAPAka.iIK.Size()));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AUTS"),
						iEAPAka.iAUTS.Ptr(),
						iEAPAka.iAUTS.Size()));
										
				iQueryId = EQueryNone;

				delete iAuthenticationData;
				iAuthenticationData = NULL;	
						
				// Close the custom API since we don't need it any more.
				iCustomAPI.Close();				
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::RunL() - KErrNone case: CLOSED CUSTOM API \n")));
				
				completion_status = res.set_buffer(iEAPAka.iRES.Ptr(), iEAPAka.iRES.Size(), false, false);
				if (completion_status != eap_status_ok)
				{
					res.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not set buffer for RES.\n")));
					break;
				}

				completion_status = ck.set_buffer(iEAPAka.iCK.Ptr(), iEAPAka.iCK.Size(), false, false);
				if (completion_status != eap_status_ok)
				{
					ck.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not set buffer for CK.\n")));
					break;
				}

				completion_status = ik.set_buffer(iEAPAka.iIK.Ptr(), iEAPAka.iIK.Size(), false, false);
				if (completion_status != eap_status_ok)
				{
					ik.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not set buffer for IK.\n")));
					break;
				}

				completion_status = auts.set_buffer(iEAPAka.iAUTS.Ptr(), iEAPAka.iAUTS.Size(), false, false);
				if (completion_status != eap_status_ok)
				{
					auts.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not set buffer for AUTS.\n")));
					break;
				}
			
				// Complete. This happens only if completion_status is eap_status_ok so far.		
				TRAP(error, iParent->complete_AKA_RES_L( &res, &ck, &ik, &auts ) );			
			
			break;
		}
	} 
	else 
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Got error reply.\n")));	
	
		switch( iQueryId )
		{
			case EQueryIMSI:
			
				// Error with IMSI. Reset it and complete the request.			
				iQueryId = EQueryNone;
				imsi.reset();
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Error in IMSI.\n")));
							
				TRAP(error, iParent->complete_AKA_imsi_L(&imsi));
			break;
			
			case EQueryRES:
			
				// Re-synchronization needed or error with RES or CK or IK.
				
				// We have to close the custom API anyway. 
				iQueryId = EQueryNone;
				iCustomAPI.Close();				
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::RunL() - error case: CLOSED CUSTOM API \n")));
				
				// Just to verify if there is any values set.
				
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("RES"),
						iEAPAka.iRES.Ptr(),
						iEAPAka.iRES.Size()));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CK"),
						iEAPAka.iCK.Ptr(),
						iEAPAka.iCK.Size()));

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("IK"),
						iEAPAka.iIK.Ptr(),
						iEAPAka.iIK.Size()));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AUTS"),
						iEAPAka.iAUTS.Ptr(),
						iEAPAka.iAUTS.Size()));				
				
				// Complete the request after resetting res, ck and ik.
				// auts might have some value if the error is related to re-synchronization. So don't reset it.
				res.reset();
				ck.reset();
				ik.reset();
				
				completion_status = auts.set_buffer(iEAPAka.iAUTS.Ptr(), iEAPAka.iAUTS.Size(), false, false);
				if (completion_status != eap_status_ok)
				{
					auts.reset();
					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("AKA interface: Could not set buffer for AUTS.\n")));
					break;
				}
				
				// Check if the failure is due to re-synchronization fail.
				if(	iStatus.Int() == KErrMMEtelSqnVerificationFailed ) 
				{
					// Re-synchronization failure.
					AuthenticationStatus = eap_status_syncronization_failure;
				}
				else
				{
					// Authentication failed. Errors could be KErrMMEtelMacVerificationFailed or KErrMMEtelAuthenticateFailed also.
					AuthenticationStatus = eap_status_authentication_failure;
				}
			
				// Complete. This happens only if completion_status is eap_status_ok so far.
				TRAP(error, iParent->complete_AKA_RES_L( &res, &ck, &ik, &auts, AuthenticationStatus, completion_status ) );
			break;
		}
	}
	
	if( completion_status != eap_status_ok  && iQueryId == EQueryIMSI )
	{
		TRAP(error, iParent->complete_AKA_imsi_L(&imsi, completion_status));		
	}

	if( completion_status != eap_status_ok  && iQueryId == EQueryRES )
	{
		TRAP(error, iParent->complete_AKA_RES_L( &res, &ck, &ik, &auts, AuthenticationStatus, completion_status ) );
	}	

	DisconnectMMETel();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

TInt CEapAkaInterface::CreateMMETelConnectionL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::CreateMMETelConnectionL()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::CreateMMETelConnectionL()");

	TInt errorCode = KErrNone;
	
	// MMETel need to be connected only once.    
    if( !iMMETELConnectionStatus )
    {
		RTelServer::TPhoneInfo phoneInfo;
		TInt phoneCount = 0;

		// Connect to ETel server
		User::LeaveIfError( iServer.Connect() ); 	
		
	    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Connected to ETel server.\n")));	

		// This function loads an ETel TSY module, mmtsy.
		errorCode = iServer.LoadPhoneModule( KMmTsyModuleName );	
		
	    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Loaded phone module.\n")));	    
		
		if ( errorCode != KErrNone && errorCode != KErrAlreadyExists )
		{
			User::Leave( errorCode );
		}

		iServer.SetExtendedErrorGranularity( RTelServer::EErrorExtended );

		// This function retrieves the total number of phones supported by all 
		// the currently loaded ETel (TSY) modules.
		User::LeaveIfError( iServer.EnumeratePhones( phoneCount ) );	
		
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Number of phones supported by the loaded ETel = %d.\n"), phoneCount));
		
		// This function retrieves information associated with the specified phone
		while ( ( phoneCount-- ) && ( phoneInfo.iName != KMmTsyPhoneName ) ) 
		{ 
			User::LeaveIfError( iServer.GetPhoneInfo( phoneCount, phoneInfo ) );		
			
		    EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Got phone info.\n")));
		} 

		// This function opens a phone subsession by name. ("DefaultPhone").
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

void CEapAkaInterface::DisconnectMMETel()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapAkaInterface::DisconnectMMETel()\n")));
	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: CEapAkaInterface::DisconnectMMETel()");

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
