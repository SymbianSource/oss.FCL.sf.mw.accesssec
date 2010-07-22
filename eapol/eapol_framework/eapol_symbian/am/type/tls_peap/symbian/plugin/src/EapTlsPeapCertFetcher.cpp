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
* %version: %
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
#include <EapTraceSymbian.h>
#include <AbsEapCertificateFetcher.h>

#include <x509cert.h>
#include <X509CertNameParser.h>
#include <x509certext.h>


// ================= MEMBER FUNCTIONS =======================

CEapTlsPeapCertFetcher* CEapTlsPeapCertFetcher::NewL(CAbsEapCertificateFetcher* const aParent)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::NewL(CAbsEapCertificateFetcher)\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::NewL(CAbsEapCertificateFetcher)\n"));

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
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::NewL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::NewL()\n"));

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

CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher(CAbsEapCertificateFetcher* const aParent)
: CActive(CActive::EPriorityStandard)
, iState(EGetCertificatesNone)
, iParent(aParent)
, iEncodedCertificate(0)
, iCertPtr(0,0)
, iOwnertype(EUserCertificate)
, iCertInfoIndex(0)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher(CAbsEapCertificateFetcher)\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher(CAbsEapCertificateFetcher)\n"));

}

//--------------------------------------------------

// DON'T USE THIS FUNCTION. THIS IS ONLY FOR EapTlsPeapUtils. 	
CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher()
: CActive(CActive::EPriorityStandard)
, iState(EGetCertificatesNone)
, iParent(NULL)
, iEncodedCertificate(0)
, iCertPtr(0,0)
, iOwnertype(EUserCertificate)
, iCertInfoIndex(0)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::CEapTlsPeapCertFetcher()\n"));

}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::ConstructL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::ConstructL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::ConstructL()\n"));

	User::LeaveIfError(iFs.Connect());

	CActiveScheduler::Add(this);
	
	iEncodedCertificate = HBufC8::NewL(0);
	iCertPtr.Set(iEncodedCertificate->Des());	

}

//--------------------------------------------------

CEapTlsPeapCertFetcher::~CEapTlsPeapCertFetcher()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::~CEapTlsPeapCertFetcher()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::~CEapTlsPeapCertFetcher()\n"));

	// Delete iCertInfos
	for (TInt i = 0; i < iCertInfos.Count(); i++)
	{
		iCertInfos[i]->Release();
	}
	iCertInfos.Reset();

	iCACerts.ResetAndDestroy();

	iUserCerts.ResetAndDestroy();

	delete iCertFilter;
	iCertFilter = 0;

	delete iCertStore;
	iCertStore = 0;

	delete iEncodedCertificate;
	iEncodedCertificate = 0;

	iFs.Close();

	if(IsActive())
	{
		Cancel();		
	}
}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::GetCertificatesL()
{	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::GetCertificatesL()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::GetCertificatesL()\n"));

	iCACerts.ResetAndDestroy();

	iUserCerts.ResetAndDestroy();

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

//--------------------------------------------------

void CEapTlsPeapCertFetcher::DoCancel()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::DoCancel()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::DoCancel()\n"));

}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::InitializeQuery()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::InitializeQuery(): iOwnertype=%d\n"),
		iOwnertype));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::InitializeQuery()\n"));

	// Delete iCertInfos
	for (TInt i = 0; i < iCertInfos.Count(); i++)
	{
		iCertInfos[i]->Release();
	}
	iCertInfos.Reset();

	delete iCertFilter;
	iCertFilter = 0;

	TRAPD(error, iCertFilter = CCertAttributeFilter::NewL());
	if (error != KErrNone)
	{
		// Complete with empty lists
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapCertFetcher::InitializeQuery() -  Complete with empty lists Error:%d, iUserCerts.Count()=%d, iCACerts.Count()=%d\n"),
			error,
			iUserCerts.Count(),
			iCACerts.Count()) );
		TRAP(error, iParent->CompleteReadCertificatesL(iUserCerts, iCACerts));
		return;
	}
	iCertFilter->SetFormat(EX509Certificate);

	iCertFilter->SetOwnerType(iOwnertype);

	iCertInfoIndex = 0;

	iState = EGetCertificatesGetCertList;

	iCertStore->List(
		iCertInfos,
		*iCertFilter, 
		iStatus);

	SetActive();		
}

//--------------------------------------------------

void CEapTlsPeapCertFetcher::RunL()
{	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - iStatus.Int()=%d, iState=%d \n"),
		iStatus.Int() , iState));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapCertFetcher::RunL()\n"));

	//int i;
	TInt error(KErrNone);
		
	// This causes panic if leaves
	if (iStatus.Int() != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() -- don't leave...")));
	}
	
	switch (iState)
	{
	case EGetCertificatesInitStore:
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - EGetCertificatesInitStore\n")));

			// First get the User certificates.
			iOwnertype = EUserCertificate;
			InitializeQuery();
		}
		break;

	case EGetCertificatesRetrieveCert:
		{			
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - EGetCertificatesRetrieveCert - Symbian cert store found %d certs in device\n"),
				iCertInfos.Count()));

			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() - iWait.Start() returned, iStatus.Int()=%d \n"),iStatus.Int() ) );

			CCTCertInfo* CertInfo = iCertInfos[iCertInfoIndex];
			CCertificate* cert = NULL;

			if ( iStatus.Int() == KErrNone )
			{
				switch ( CertInfo->CertificateFormat() )
				{
				case EX509Certificate:
					{
						TRAPD(error, cert = CX509Certificate::NewL( iCertPtr ));
						if (error != KErrNone)
						{
							EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapCertFetcher::RunL() - EGetCertificatesGetCertList - leave from CX509Certificate::NewL Label:%S Error:%d\n"),
							&(CertInfo->Label()),
							error ) );

							cert = NULL;
						}
					break;
					}
				default:
					{
		                // Only  X509 type of certificates are supported at the moment.
		                // This won't be happening ever since we have used a filter while getting the certificate list.
						EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapCertFetcher::RunL() - Unsupported Certificate - Not X509\n") ) );
						
						cert = NULL;
					}
				}
			}
			else
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapCertFetcher::RunL() - Error from Certificate retrieve, iStatus.Int()=%d\n"), iStatus.Int() ) );
			}

			if( cert != NULL )
			{
				HBufC* pri = NULL;
				HBufC* sec = NULL;
			
				CleanupStack::PushL(cert);
				
				X509CertNameParser::PrimaryAndSecondaryNameL( *((CX509Certificate*)cert), pri, sec, CertInfo->Label());
	
				CleanupStack::PopAndDestroy(cert);

				CleanupStack::PushL(pri);
				CleanupStack::PushL(sec);


				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() - Label=%S, Pri name=%S,Length=%d, Sec name=%S,Length=%d\n"),
					 &(CertInfo->Label()), pri, pri->Length(), sec, sec->Length() ) );

				EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "CEapTlsPeapCertFetcher::RunL() - Sub Key Id:", (CertInfo->SubjectKeyId().Ptr()), 
						(CertInfo->SubjectKeyId().Size()) ) );

				EapCertificateEntry * const certEntry = new EapCertificateEntry;
				if (certEntry == 0)
				{
					User::Leave(KErrNoMemory);
				}
				CleanupStack::PushL(certEntry);

				certEntry->SetLabel(CertInfo->Label());
				certEntry->SetSubjectKeyId(CertInfo->SubjectKeyId());

				// Copy the new fields. Primary and secondary name.				
				certEntry->SetPrimaryName(pri->Des().Left(KMaxCertNameLength));
				certEntry->SetSecondaryName(sec->Des().Left(KMaxCertNameLength));

				if (CertInfo->CertificateOwnerType() == ECACertificate)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - CA certificate\n")));

					certEntry->SetCertType(EapCertificateEntry::ECA);
					error = iCACerts.Append(certEntry);	
				}
				else if (CertInfo->CertificateOwnerType() == EUserCertificate)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - User certificate\n")));

					certEntry->SetCertType(EapCertificateEntry::EUser);
					error = iUserCerts.Append(certEntry);
				}
				else
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - Unknown certificate\n")));
				}

				if (error == KErrNone)
				{
					CleanupStack::Pop(certEntry);
				}
				else
				{
					CleanupStack::PopAndDestroy(certEntry);
				}

				CleanupStack::PopAndDestroy(sec);
				CleanupStack::PopAndDestroy(pri);

			}

			++iCertInfoIndex;
		}

		// Here MUST NOT be break. State EGetCertificatesGetCertList is run after the state EGetCertificatesRetrieveCert.

	case EGetCertificatesGetCertList:
		{			
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL(): - EGetCertificatesGetCertList - Symbian cert store found %d certs in device, iCertInfoIndex=%d\n"),
				iCertInfos.Count(),
				iCertInfoIndex));
		
			if (iCertInfoIndex < iCertInfos.Count())
			{				
				CCTCertInfo* CertInfo = iCertInfos[iCertInfoIndex];

				iEncodedCertificate->Des().SetLength(0);
				
				TRAPD(error, iEncodedCertificate = iEncodedCertificate->ReAllocL(CertInfo->Size()));
				if (error != KErrNone)
				{
					EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapCertFetcher::RunL() -  EGetCertificatesGetCertList - leave from iEncodedCertificate->ReAllocL Error:%d\n"), error ) );
				}		
				iCertPtr.Set(iEncodedCertificate->Des());

				EAP_TRACE_DEBUG_SYMBIAN((_L("\nCEapTlsPeapCertFetcher::RunL() - EGetCertificatesGetCertList - Retreiving cert %d\n"), iCertInfoIndex ) );
				
				iState = EGetCertificatesRetrieveCert;

				iCertStore->Retrieve( *CertInfo, iCertPtr, iStatus);

				SetActive();
			}
			else if (iOwnertype == EUserCertificate)
			{
				// Next get the CA certificates.
				iOwnertype = ECACertificate;
				InitializeQuery();
				return;
			}
			else
			{
				delete iCertFilter;
				iCertFilter = 0;

				// Delete iCertInfos
				for (TInt i = 0; i < iCertInfos.Count(); i++)
				{
					iCertInfos[i]->Release();
				}
				iCertInfos.Reset();

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapCertFetcher::RunL() -  EGetCertificatesGetCertList - Complete list, iUserCerts.Count()=%d, iCACerts.Count()=%d\n"),
					iUserCerts.Count(),
					iCACerts.Count()) );

				TRAP(error, iParent->CompleteReadCertificatesL(iUserCerts, iCACerts));
				// Ignore error on purpose.			
			}
		}
		break;
	
	default:
		EAP_TRACE_DEBUG_SYMBIAN((_L("WARNING: CEapTlsPeapCertFetcher::RunL(): - default\n")));
		break;
	}
	return;
}

//--------------------------------------------------
// End of file
