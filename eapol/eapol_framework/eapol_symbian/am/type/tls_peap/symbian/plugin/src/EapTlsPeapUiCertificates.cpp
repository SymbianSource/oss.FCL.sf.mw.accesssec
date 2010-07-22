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
* %version: 52 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 423 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
//#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbDefaults.h"
#include "EapTlsPeapDbParameterNames.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiCertificates.h>
#include <EapGeneralSettings.h>
#include <AbsEapTlsPeapUiCertificates.h>
#include <EapTraceSymbian.h>
#include "EapConversion.h"
#include <EapType.h>

#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>

const TUint KCertArrayGranularity = 16;

// ----------------------------------------------------------

CEapTlsPeapUiCertificates::CEapTlsPeapUiCertificates(
	CEapTlsPeapUiConnection * const aUiConn,
	MEapTlsPeapUiCertificates * const aParent)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iUserCerts(0)
, iCACerts(0)
, iEapGeneralSettings(0)
, iParent(aParent)
, iEapTypeConnection(0)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::CEapTlsPeapUiCertificates()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::CEapTlsPeapUiCertificates()\n"));

}

// ----------------------------------------------------------

CEapTlsPeapUiCertificates::~CEapTlsPeapUiCertificates()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::~CEapTlsPeapUiCertificates()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::~CEapTlsPeapUiCertificates()\n"));

	Close();
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiCertificates::Open()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::Open()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::Open()\n"));

    if (iIsOpened)
    {
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::Open(): KErrAlreadyExists\n")));
        return KErrAlreadyExists;
    }

	TEapExpandedType aEapType(iUiConn->GetEapType());

	TRAPD(error, iEapTypeConnection = CEapType::NewL(iUiConn->GetIndexType(), iUiConn->GetIndex(), aEapType));
	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::Open(): CEapType::NewL() error=%d\n"),error));
		return error;
	}
    
    iEapTypeConnection->SetTunnelingType(iUiConn->GetTunnelingType());

    TRAP(error, iEapGeneralSettings = CEapGeneralSettings::NewL(iUiConn->GetIndexType(), iUiConn->GetIndex()));
    if (error != KErrNone)
        {
        EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::Open(): CEapGeneralSettings::NewL() error=%d\n"),error));
        return error;
        }

    iIsOpened = ETrue;

    return KErrNone;
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiCertificates::Close()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::Close()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::Close()\n"));

	if (iIsOpened == EFalse)
	{
		return KErrNone;
	}

	delete iUserCerts;
	iUserCerts = 0;

	delete iCACerts;
	iCACerts = 0;

	delete iEapGeneralSettings;
	iEapGeneralSettings = 0;

	iUiConn = NULL;

	iIsOpened = EFalse;

	return KErrNone;
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiCertificates::GetCertificates(
	RPointerArray<EapCertificateEntry> ** aUserCerts,
	RPointerArray<EapCertificateEntry> ** aCACerts)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::GetCertificates()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::GetCertificates()\n"));

	if (aUserCerts == NULL
		|| aCACerts == NULL)
    {
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::GetCertificates(): KErrArgument\n")));
        return KErrArgument;
    }

    if (iIsOpened == EFalse)
    {
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::GetCertificates(): KErrSessionClosed\n")));
        return KErrSessionClosed;
    }

    if (iUserCerts == 0)
    {
    	iUserCerts = new RPointerArray<EapCertificateEntry>(KCertArrayGranularity);
    	if (!iUserCerts)
    	{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::GetCertificates(): iUserCerts, KErrNoMemory\n")));
	        return KErrNoMemory;
	    }	
    }
    
    *aUserCerts = iUserCerts;
    
    if (iCACerts == 0)
    {
	    iCACerts = new RPointerArray<EapCertificateEntry>(KCertArrayGranularity);
	    if (!iUserCerts)
	    {
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::GetCertificates(): iCACerts, KErrNoMemory\n")));
	        return KErrNoMemory;
	    }
    }
    *aCACerts = iCACerts;
    
	TInt error(KErrNone);

	error = iEapGeneralSettings->GetCertificateLists(
		*iUserCerts,
		*iCACerts);

	if (error != KErrNone)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::GetCertificates(): GetCertificateLists() error=%d\n"),
			error));
		iParent->CompleteReadCertificates(error);
	    return error;
	}

	TRAP(error, SelectActiveCertificatesL());
	
	return error;
}

// ----------------------------------------------------------

void CEapTlsPeapUiCertificates::SelectCertificatesL(
	const EapCertificateEntry::TCertType aCertType,
	const EAPSettings & aSettings,
	RPointerArray<EapCertificateEntry>& aAvailableCerts)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::SelectCertificatesL(): - Available cert count in device aAvailableCerts.Count()=%d, aSettings.iCertificates.Count()=%d\n"),
		aAvailableCerts.Count(),
		aSettings.iCertificates.Count()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::SelectCertificatesL()\n"));

	// Loop through available certs
	TInt avail_ind(0);

	for (avail_ind = 0; avail_ind < aAvailableCerts.Count(); ++avail_ind)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::SelectCertificatesL(): loops aAvailableCerts avail_ind=%d, aAvailableCerts.Count()=%d, aSettings.iCertificates.Count()=%d\n"),
			avail_ind,
			aAvailableCerts.Count(),
			aSettings.iCertificates.Count()) );

		EapCertificateEntry * const avail_cert = aAvailableCerts[avail_ind];

		EAP_TRACE_SETTINGS(avail_cert);

		avail_cert->SetIsEnabled(EFalse);

		if (aSettings.iCertificatesPresent)
		{
			TInt select_ind(0);

			for (select_ind = 0; select_ind < aSettings.iCertificates.Count(); ++select_ind)
			{
				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::SelectCertificatesL(): loops aSettings.iCertificates select_ind=%d\n"),
					select_ind ) );

				EapCertificateEntry * const conf_cert = aSettings.iCertificates[select_ind];

				EAP_TRACE_SETTINGS(conf_cert);

				if (aCertType == conf_cert->GetCertType()
					&& avail_cert->GetSubjectKeyId() == conf_cert->GetSubjectKeyId())
				{
					avail_cert->SetIsEnabled(ETrue);

					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::SelectCertificatesL(): - Reading certificate details from the DB - Label=%S \n"),
						avail_cert->GetLabel() ) );

					EAP_TRACE_DATA_DEBUG_SYMBIAN(("Subject Key Id:",
						avail_cert->GetSubjectKeyId().Ptr(),
						avail_cert->GetSubjectKeyId().Length()));
				}
			}
		}
	}
}

// ----------------------------------------------------------

void CEapTlsPeapUiCertificates::SelectActiveCertificatesL()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::SelectActiveCertificatesL(): - Available cert count in device - USER=%d, CA=%d \n"),
		iUserCerts->Count(), iCACerts->Count()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::SelectActiveCertificatesL()\n"));

	// Now all available certificates have been read.
	// Get the allowed certs from the server and set their iIsEnabled flag -> ETrue.

    EAPSettings aSettings;
    
	TRAPD(error, iEapTypeConnection->GetConfigurationL(aSettings));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::SelectActiveCertificatesL(): GetConfigurationL(): failed %d\n"), error));
		iParent->CompleteReadCertificates(error);
		User::Leave(error);
	}

	TRAP(error, SelectCertificatesL(EapCertificateEntry::EUser, aSettings, *iUserCerts));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::SelectActiveCertificatesL(): SelectCertificatesL(iUserCerts): failed %d\n"), error));
		iParent->CompleteReadCertificates(error);
		User::Leave(error);
	}

	TRAP(error, SelectCertificatesL(EapCertificateEntry::ECA, aSettings, *iCACerts));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::SelectActiveCertificatesL(): SelectCertificatesL(iCACerts): failed %d\n"), error));
		iParent->CompleteReadCertificates(error);
		User::Leave(error);
	}

	// Operation was successful
	iParent->CompleteReadCertificates(KErrNone);
}

// ----------------------------------------------------------

void CEapTlsPeapUiCertificates::SaveCertificatesL(
	const EapCertificateEntry::TCertType /* aCertType */,
	const RPointerArray<EapCertificateEntry>* const aAvailableCerts,
	EAPSettings & aSettings)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::SaveCertificatesL(): - Available cert count %d \n"),
		aAvailableCerts->Count()));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::SaveCertificatesL()\n"));

	TInt avail_ind(0);
	for (avail_ind = 0; avail_ind < aAvailableCerts->Count(); avail_ind++)
	{
		if ((*aAvailableCerts)[avail_ind]->GetIsEnabled())
		{
			EAP_TRACE_SETTINGS((*aAvailableCerts)[avail_ind]);

			// Validate data lengths.
			if((*aAvailableCerts)[avail_ind]->GetLabel()->Length() > KMaxCertLabelLengthInDB 
				|| (*aAvailableCerts)[avail_ind]->GetSubjectKeyId().Length() > KMaxSubjectKeyIdLengthInDB)
			{
				// Too long data. Can not be stored in DB.

				EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::UpdateL(): User : Too long Label or SubjectKeyId. Length: Label=%d, SubjectKeyId=%d \n"),
					(*aAvailableCerts)[avail_ind]->GetLabel()->Length(),
					(*aAvailableCerts)[avail_ind]->GetSubjectKeyId().Length()));
								
				User::Leave(KErrArgument);
			}

#if 1

			EapCertificateEntry * const aCertEntry = (*aAvailableCerts)[avail_ind]->Copy();
			if (aCertEntry == 0)
			{
				User::Leave(KErrNoMemory);
			}
			CleanupStack::PushL(aCertEntry);

#else

			EapCertificateEntry * const aCertEntry = new EapCertificateEntry;
			if (aCertEntry == 0)
			{
				User::Leave(KErrNoMemory);
			}
			CleanupStack::PushL(aCertEntry);

			aCertEntry->SetCertType(aCertType);
			aCertEntry->GetSubjectKeyIdWritable()->Copy(*((*aAvailableCerts)[avail_ind]->GetSubjectKeyId()));

#endif

			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL(): - Wrote User cert details to the DB - Label=%S \n"),
				aCertEntry->GetLabel() ) );
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "Subject Key Id:",
				aCertEntry->GetSubjectKeyId().Ptr(),
				aCertEntry->GetSubjectKeyId().Length() ) );

			EAP_TRACE_SETTINGS(aCertEntry);

			aSettings.iCertificates.AppendL(aCertEntry);

			aSettings.iCertificatesPresent = ETrue;

			CleanupStack::Pop(aCertEntry);
		}
	}
}

// ----------------------------------------------------------

TInt CEapTlsPeapUiCertificates::Update()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::Update()\n")));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapTlsPeapUiCertificates::Update()\n"));

    EAPSettings aSettings;
    
	TRAPD(error, SaveCertificatesL(EapCertificateEntry::EUser, iUserCerts, aSettings));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::Update() SaveCertificatesL(iUserCerts): failed %d\n"), error));
		iParent->CompleteReadCertificates(error);
		return error;
	}

	TRAP(error, SaveCertificatesL(EapCertificateEntry::ECA, iCACerts, aSettings));
	if (error)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: CEapTlsPeapUiCertificates::Update() SaveCertificatesL(iCACerts): failed %d\n"), error));
		iParent->CompleteReadCertificates(error);
		return error;
	}

	TRAP(error,iEapTypeConnection->SetConfigurationL(aSettings));

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::Update(): error = %d\n"),error));

	return error;
}

// ----------------------------------------------------------
// End of file
