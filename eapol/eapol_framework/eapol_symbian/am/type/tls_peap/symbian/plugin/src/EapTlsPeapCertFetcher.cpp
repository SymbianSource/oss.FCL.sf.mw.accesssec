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
* %version: 31 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 414 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapTlsPeapCertFetcher.h"
#include <EapTlsPeapUiCertificates.h>
#include "eap_am_trace_symbian.h"

#include <x509cert.h>
#include <X509CertNameParser.h>
#include <x509certext.h>


// ================= MEMBER FUNCTIONS =======================

CEapTlsPeapCertFetcher* CEapTlsPeapCertFetcher::NewL(CEapTlsPeapUiCertificates* const aParent)
{
	CEapTlsPeapCertFetcher* self = new(ELeave) CEapTlsPeapCertFetcher(aParent);
	CleanupStack::PushL(self);
	self->ConstructL();
	CleanupStack::Pop();
	return self;
}

//--------------------------------------------------

// DON'T USE THIS FUNCTION. THIS IS ONLY FOR EapTlsPeapUtils. 	
CEapTlsPeapCertFetcher* CEapTlsPeapCertFetcher::NewL()
{
	CEapTlsPeapCertFetcher* self = new(ELeave) CEapTlsPeapCertFetcher();
	CleanupStack::PushL(self);

	/************* THIS PART MAY NOT BE NEEDED AT ALL. NOT A GOOD IDEA TO INSTALL SCHEDULER HERE ****************/
	// Check if we are in a scheduler already.
	CActiveScheduler* scheduler = NULL;
	scheduler = CActiveScheduler::Current();
	
	// There may not be a default scheduler if called from EapTlsPeapUtils for the first time.
	// Hence need to add one. Otherwise no need to install another.
	if( scheduler == NULL )
	{
	
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::NewL -No default scheduler!!\n") ) );
	
		scheduler = new (ELeave) CActiveScheduler();
		CActiveScheduler::Install(scheduler);		
	}
	/*****************************/
	
	self->ConstructL();
	CleanupStack::Pop();	
	
	return self;
}

//--------------------------------------------------

CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher(CEapTlsPeapUiCertificates* const aParent)
: CActive(CActive::EPriorityStandard)
, iParent(aParent)
, iEncodedCertificate(0)
, iCertPtr(0,0)
{
}

//--------------------------------------------------

// DON'T USE THIS FUNCTION. THIS IS ONLY FOR EapTlsPeapUtils. 	
CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher()
: CActive(CActive::EPriorityStandard)
, iParent(NULL)
, iEncodedCertificate(0)
, iCertPtr(0,0)
{
}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::ConstructL()
{
	User::LeaveIfError(iFs.Connect());

	CActiveScheduler::Add(this);
	
	iEncodedCertificate = HBufC8::NewL(0);
	iCertPtr.Set(iEncodedCertificate->Des());	

}

//--------------------------------------------------

CEapTlsPeapCertFetcher::~CEapTlsPeapCertFetcher()
{
	// Delete iCertInfos
	for (TInt i = 0; i < iCertInfos.Count(); i++)
	{
		iCertInfos[i]->Release();
	}
	iCertInfos.Reset();

	iCACerts.Reset();

	iUserCerts.Reset();
		
	delete iCertFilter;
	
	delete iCertStore;
	
	delete iEncodedCertificate;	
	
	iFs.Close();

	if(IsActive())
	{
		Cancel();		
	}
}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::GetCertificatesL()
{	
	iState = EGetCertificatesInitStore;
	if (iCertStore == 0)
	{
		iCertStore = CUnifiedCertStore::NewL(iFs, false);
		iCertStore->Initialize(iStatus);		
	}
	else
	{
		TRequestStatus* status = &iStatus;
		User::RequestComplete(status, KErrNone);		
	}
	SetActive();
}


void CEapTlsPeapCertFetcher::DoCancel()
{
}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::RunL()
{	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL - iStatus.Int()=%d, iState=%d \n"),
	iStatus.Int() , iState));
	if( iState == EGetSymbianSubjectKeyId )
	{
		// Only for GetSymbianSubjectKeyIdL.
		iWait.AsyncStop(); // This is needed to continue the execution after Wait.Start()
		return; // No need to proceed further.
	}
	
	if( iState == EGetCertificatesRetrieveCert)
	{
		// This is executed when certificate details are being retrieved.
		iWait.AsyncStop(); // This is needed to continue the execution after Wait.Start()
		return; // No need to proceed further.
	}
	
	int i;
	TInt err(KErrNone);
		
	// This causes panic if leaves
	if (iStatus.Int() != KErrNone)
	{
RDebug::Print(_L("CEapTlsPeapCertFetcher::RunL() -- don't leave..."));
	}
	
	switch (iState)
	{
	case EGetCertificatesInitStore:
		{
			// Delete iCertInfos
			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();
		
			delete iCertFilter;
			iCertFilter = 0;
		
			TRAP(err, iCertFilter = CCertAttributeFilter::NewL());
			if (err != KErrNone)
			{
				// Complete with empty lists
				TInt err(KErrNone);
				TRAP(err, iParent->CompleteReadCertificatesL(iUserCerts, iCACerts));
				break;
			}
			iCertFilter->SetFormat(EX509Certificate);

			iState = EGetCertificatesGetCertList;
			iCertStore->List(
				iCertInfos,
				*iCertFilter, 
				iStatus);
			SetActive();		
		}
		break;

	case EGetCertificatesGetCertList:
		{			
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL - EGetCertificatesGetCertList - Symbian cert store found %d certs in device\n"),
			iCertInfos.Count()));
		
			if(0 == iCertInfos.Count())
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR : CEapTlsPeapCertFetcher::RunL - SERIOUS PROBLEM - Symbian cert store couldn't find any certs in device\n")));				
			}
		
			for (i = 0; i < iCertInfos.Count(); i++)
			{				
			    CCTCertInfo* CertInfo;
				CertInfo = iCertInfos[i];
				iEncodedCertificate->Des().SetLength(0);
				
				TRAPD(err, iEncodedCertificate = iEncodedCertificate->ReAllocL(iCertInfos[i]->Size()));
				if (err != KErrNone)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("\nCEapTlsPeapCertFetcher::RunL() -  EGetCertificatesGetCertList - leave from iEncodedCertificate->ReAllocL Error:%d\n"), err ) );
				}		
				iCertPtr.Set(iEncodedCertificate->Des());

				EAP_TRACE_DEBUG_SYMBIAN((_L("\nCEapTlsPeapCertFetcher::RunL() - EGetCertificatesGetCertList - Retreiving cert %d\n"), i ) );
				
			    iCertStore->Retrieve( *CertInfo, iCertPtr, iStatus);
			    
			    iState = EGetCertificatesRetrieveCert;

			    SetActive();
			    iWait.Start();
			 	
				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() - iWait.Start() returned, iStatus.Int()=%d \n"),iStatus.Int() ) );

			 	CCertificate* cert = NULL;

			    if ( iStatus.Int() == KErrNone )
		        {
			        switch ( CertInfo->CertificateFormat() )
		            {
		            case EX509Certificate:
		                {
		                TRAPD(err, cert = CX509Certificate::NewL( iCertPtr ));
			            if (err != KErrNone)
			               	EAP_TRACE_DEBUG_SYMBIAN((_L("\nCEapTlsPeapCertFetcher::RunL() - EGetCertificatesGetCertList - leave from CX509Certificate::NewL Label:%S Error:%d\n"),&(CertInfo->Label()), err ) );
			            break;
		                }
		            default:
		                {
		                	// Only  X509 type of certificates are supported at the moment.
		                	// This won't be happening ever since we have used a filter while getting the certificate list.
							EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() - Unsupported Certificate - Not X509\n") ) );
							
			                break;
		                }
		            }
		        }
		        else
		        {
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() - Error from Certificate retrieve, iStatus.Int()=%d\n"), iStatus.Int() ) );
		        }

				if( cert == NULL )
				{
					// Some problem above. Skip the below and go for the next certificate.
					continue;
				}							
			
                HBufC* pri = NULL;
                HBufC* sec = NULL;
			
				CleanupStack::PushL( cert );
				
                X509CertNameParser::PrimaryAndSecondaryNameL( *((CX509Certificate*)cert), pri, sec, CertInfo->Label());
	
				CleanupStack::PopAndDestroy(); // cert		

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() - Label=%S, Pri name=%S,Length=%d, Sec name=%S,Length=%d\n"),
					 &(CertInfo->Label()), pri, pri->Length(), sec, sec->Length() ) );

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "CEapTlsPeapCertFetcher::RunL() - Sub Key Id:", (CertInfo->SubjectKeyId().Ptr()), 
						(CertInfo->SubjectKeyId().Size()) ) );

				SCertEntry certEntry;
							
				certEntry.iLabel.Copy(iCertInfos[i]->Label());
				certEntry.iSubjectKeyId.Copy(iCertInfos[i]->SubjectKeyId());
				
				// Copy the new fields. Primary and secondary name.				
				certEntry.iPrimaryName.Copy( pri->Des().Left(KMaxNameLength ) );
				certEntry.iSecondaryName.Copy( sec->Des().Left(KMaxNameLength ) );
				
				delete pri;
				delete sec;
				
				if (iCertInfos[i]->CertificateOwnerType() == ECACertificate)
				{
					iCACerts.Append(certEntry);	
				}
				else if (iCertInfos[i]->CertificateOwnerType() == EUserCertificate)
				{
					iUserCerts.Append(certEntry);
				}				
			}
			delete iCertFilter;
			iCertFilter = 0;

			// Delete iCertInfos
			for (TInt i = 0; i < iCertInfos.Count(); i++)
			{
				iCertInfos[i]->Release();
			}
			iCertInfos.Reset();
			TRAP(err, iParent->CompleteReadCertificatesL(iUserCerts, iCACerts));
			// Ignore error on purpose.			
		}
		break;
	
	default:
		break;
	}
	return;
}

// End of file
