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
* %version: 6.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 174 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

// INCLUDE FILES
#include "EapProtectedSetupInterface.h"
#include "eap_am_type_protected_setup_symbian.h"

#include <mmtsy_names.h>
#include <etelmmerr.h>

// ================= MEMBER FUNCTIONS =======================

CEapProtectedSetupInterface::CEapProtectedSetupInterface(abs_eap_am_tools_c* const aTools, CEapAmProtectedSetupSymbian* const aParent)
: CActive(CActive::EPriorityStandard)
, iParent(aParent)
, m_am_tools(aTools)
, iQueryId(EQueryNone)
, iMMETELConnectionStatus(EFalse)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapProtectedSetupInterface* CEapProtectedSetupInterface::NewL(abs_eap_am_tools_c* const aTools, 
											   CEapAmProtectedSetupSymbian* const aParent)
{
	CEapProtectedSetupInterface* self = new(ELeave) CEapProtectedSetupInterface(aTools, aParent);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

void CEapProtectedSetupInterface::ConstructL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	CActiveScheduler::Add(this);	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

CEapProtectedSetupInterface::~CEapProtectedSetupInterface()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if(IsActive())
	{
		Cancel();		
	}
	
	DisconnectMMETel();	
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

void CEapProtectedSetupInterface::QueryDeviceParametersL()
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ProtectedSetup interface: Querying Device Parametes.\n")));
	
	iQueryId = EQueryDeviceParams;
		
	// Create MMETEl connection.
	User::LeaveIfError( CreateMMETelConnectionL() );
	
  iPhone.GetPhoneId( iStatus, iDeviceId ); 
 	
	if( !IsActive() )
	{
		SetActive();
	}  

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------
 
void CEapProtectedSetupInterface::DoCancel()
{
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapProtectedSetupInterface::DoCancel() - Cancelling MMETEL query.\n") ) );

	if(iQueryId == EQueryDeviceParams)
	{
		// Cancel the request for device id.
		iPhone.CancelAsyncRequest(EMobilePhoneGetPhoneId);
	}
	else
	{
		// This should not happen.
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: CEapProtectedSetupInterface::DoCancel(): SOME BIG PROBLEM \n")));	
	}
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapProtectedSetupInterface::DoCancel(): CANCELLED the REQUEST \n")));
}

//--------------------------------------------------

void CEapProtectedSetupInterface::RunL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapProtectedSetupInterface::RunL(). iStatus.Int() =%d \n"), iStatus.Int() ));
	
	TInt error = KErrNone;
	eap_status_e completion_status(eap_status_ok);
	
	if (iStatus.Int() == KErrNone)
	{	
		switch( iQueryId )
		{
			case EQueryDeviceParams:
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("CEapProtectedSetupInterface::RunL():: Got Device ID reply.\n")));
						
				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Manufacturer"),
						iDeviceId.iManufacturer.Ptr(),
						iDeviceId.iManufacturer.Size()));

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Model"),
						iDeviceId.iModel.Ptr(),
						iDeviceId.iModel.Size()));

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Revision"),
						iDeviceId.iRevision.Ptr(),
						iDeviceId.iRevision.Size()));

				EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("SerialNumber"),
						iDeviceId.iSerialNumber .Ptr(),
						iDeviceId.iSerialNumber .Size()));
						
				// Complete. This happens only if completion_status is eap_status_ok so far.
				TRAP(error, iParent->complete_protected_setup_device_paramsL(iDeviceId, completion_status));
			
				break;
			
			default:
			
				// Some problem 
				// This should not happen.
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: CEapProtectedSetupInterface::RunL(): Unknown query completed.\n")));	
				break;
		}
	} 
	else 
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: CEapProtectedSetupInterface::RunL(): Got error reply.\n")));	
	
		switch( iQueryId )
		{
			case EQueryDeviceParams:
			
				// Error with Device id request. Complete the request with error.			
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: CEapProtectedSetupInterface::RunL(): Error in device parameters query.\n")));
							
				TRAP(error, iParent->complete_protected_setup_device_paramsL(
					iDeviceId, 
					m_am_tools->convert_am_error_to_eapol_error(iStatus.Int())));
				break;
			
			default:
			
				// Some problem 
				// This should not happen.
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("ERROR: CEapProtectedSetupInterface::RunL(): Unknown query failed.\n")));	
				
			break;
			
		}
	}

	DisconnectMMETel();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
}

//--------------------------------------------------

TInt CEapProtectedSetupInterface::CreateMMETelConnectionL()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Creating MMETel connection.\n")));

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

//--------------------------------------------------

void CEapProtectedSetupInterface::DisconnectMMETel()
{
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

//--------------------------------------------------

// End of file.
