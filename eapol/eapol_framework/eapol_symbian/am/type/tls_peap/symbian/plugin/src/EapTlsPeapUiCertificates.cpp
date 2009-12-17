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


// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 423 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <e32base.h>
#include "EapTlsPeapUtils.h"
#include "EapTlsPeapDbDefaults.h"
#include "EapTlsPeapDbParameterNames.h"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiCertificates.h>
#include <EapTlsPeapUiCertificate.h>
#include "EapTlsPeapCertFetcher.h"
#include <AbsEapTlsPeapUiCertificates.h>
#include "eap_am_trace_symbian.h"

#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>

const TUint KMaxSqlQueryLength = 256;
const TUint KCertArrayGranularity = 16;

CEapTlsPeapUiCertificates::CEapTlsPeapUiCertificates(
	CEapTlsPeapUiConnection * const aUiConn,
	MEapTlsPeapUiCertificates * const aParent)
: iIsOpened(EFalse)
, iUiConn(aUiConn)
, iUserCerts(0)
, iCACerts(0)
, iParent(aParent)
{
}


CEapTlsPeapUiCertificates::~CEapTlsPeapUiCertificates()
{
    if (iUiConn)
    {
        Close();
        iUiConn = NULL;
    }
}


TInt CEapTlsPeapUiCertificates::Open()
{
    if (iIsOpened)
    {
        return KErrAlreadyExists;
    }

    TInt err = iUiConn->GetDatabase(iDatabase);
    if (err != KErrNone)
    {
        return err;
    }

	TRAP(err, iCertFetcher = CEapTlsPeapCertFetcher::NewL(this));
	if (err != KErrNone)
	{
		return err;
	}

    iIsOpened = ETrue;

    return KErrNone;
}


TInt CEapTlsPeapUiCertificates::Close()
{
    if (iIsOpened == EFalse)
    {
        return KErrNone;
    }

    delete iUserCerts;
    iUserCerts = 0;
    
    delete iCACerts;
    iCACerts = 0;
    
    delete iCertFetcher;
	iCertFetcher = 0;
	    
    iUiConn = NULL;
    return KErrNone;
}

TInt CEapTlsPeapUiCertificates::GetCertificates(CArrayFixFlat<TEapTlsPeapUiCertificate> ** aUserCerts,
					CArrayFixFlat<TEapTlsPeapUiCertificate> ** aCACerts)
{
	if (aUserCerts == NULL
		|| aCACerts == NULL)
    {
        return KErrArgument;
    }
    if (iIsOpened == EFalse)
    {
        return KErrSessionClosed;
    }
    if (iUserCerts == 0)
    {
    	iUserCerts = new CArrayFixFlat<TEapTlsPeapUiCertificate>(KCertArrayGranularity);
    	if (!iUserCerts)
    	{
	        return KErrNoMemory;
	    }	
    }
    
    *aUserCerts = iUserCerts;
    
    if (iCACerts == 0)
    {
	    iCACerts = new CArrayFixFlat<TEapTlsPeapUiCertificate>(KCertArrayGranularity);
	    if (!iUserCerts)
	    {
	        return KErrNoMemory;
	    }
    }
    *aCACerts = iCACerts;
    
	TRAPD(err, iCertFetcher->GetCertificatesL());
	
	return err;
}
						 

void CEapTlsPeapUiCertificates::CompleteReadCertificatesL(
		const RArray<SCertEntry>& aAvailableUserCerts, 
		const RArray<SCertEntry>& aAvailableCACerts)
{

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::CompleteReadCertificatesL - Available cert count in device - USER=%d, CA=%d \n"),
	aAvailableUserCerts.Count(), aAvailableCACerts.Count()));

	// Now all available certificates have been read.
	// Get the allowed certs from the database and set their iIsEnabled flag -> ETrue.
    TInt err(KErrNone);
	if (iUiConn->GetEapType() == eap_type_tls)
	{
		TRAP(err, FetchDataL(KTlsAllowedUserCertsDatabaseTableName, aAvailableUserCerts, iUserCerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::CompleteReadCertificatesL -TLS- USER cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
		TRAP(err, FetchDataL(KTlsAllowedCACertsDatabaseTableName, aAvailableCACerts, iCACerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::CompleteReadCertificatesL -TLS- CA cert - LEAVE from FetchDataL err=%d\n"),
			err));

			iParent->CompleteReadCertificates(err);
			return;
		}
		
	}
	else if (iUiConn->GetEapType() == eap_type_peap)
	{	
	
		TRAP(err, FetchDataL(KPeapAllowedUserCertsDatabaseTableName, aAvailableUserCerts, iUserCerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::CompleteReadCertificatesL -PEAP- USER cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
		TRAP(err, FetchDataL(KPeapAllowedCACertsDatabaseTableName, aAvailableCACerts, iCACerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::CompleteReadCertificatesL -PEAP- CA cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
	}
	else if (iUiConn->GetEapType() == eap_type_ttls || iUiConn->GetEapType() == eap_type_ttls_plain_pap)
	{	
	
		TRAP(err, FetchDataL(KTtlsAllowedUserCertsDatabaseTableName, aAvailableUserCerts, iUserCerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L(
			"CEapTlsPeapUiCertificates::CompleteReadCertificatesL -TTLS- USER cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
		TRAP(err, FetchDataL(KTtlsAllowedCACertsDatabaseTableName, aAvailableCACerts, iCACerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L(
			"CEapTlsPeapUiCertificates::CompleteReadCertificatesL -TTLS- CA cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
	}
	
#ifdef USE_FAST_EAP_TYPE
	else if (iUiConn->GetEapType() == eap_type_fast)
	{	
	
		TRAP(err, FetchDataL(KFastAllowedUserCertsDatabaseTableName, aAvailableUserCerts, iUserCerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L(
			"CEapTlsPeapUiCertificates::CompleteReadCertificatesL -FAST- USER cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
		TRAP(err, FetchDataL(KFastAllowedCACertsDatabaseTableName, aAvailableCACerts, iCACerts));
		if (err != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L(
			"CEapTlsPeapUiCertificates::CompleteReadCertificatesL -FAST- CA cert - LEAVE from FetchDataL err=%d\n"),
			err));
		
			iParent->CompleteReadCertificates(err);
			return;
		}
	}
#endif //#ifdef USE_FAST_EAP_TYPE
	
	else 
	{
		iParent->CompleteReadCertificates(KErrNotSupported);
		return;
	}
	
	// Operation was successful
	iParent->CompleteReadCertificates(KErrNone);
}

void CEapTlsPeapUiCertificates::FetchDataL(
	const TDesC& aTableName,
	const RArray<SCertEntry>& aAvailableCerts,
	CArrayFixFlat<TEapTlsPeapUiCertificate>* const aArray)
{

	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::FetchDataL - Fetching & comparing cert details from table:%S\n"),
	&aTableName));

	aArray->Reset();
	
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// Form the query. Query everything.
	_LIT(KSQLQuery, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");

	sqlStatement.Format(KSQLQuery,						
						&aTableName,
						&KServiceType,
						iUiConn->GetIndexType(),
						&KServiceIndex,
						iUiConn->GetIndex(),
						&KTunnelingType, 
						iUiConn->GetTunnelingType());
	
	// Evaluate view
	RDbView view;
	User::LeaveIfError(view.Prepare(iDatabase, TDbQuery(sqlStatement)));
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());	
	
	// Get column set so we get the correct column numbers
	CDbColSet* colSet = view.ColSetL();
	CleanupStack::PushL(colSet);
	
	TEapTlsPeapUiCertificate tmp;
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::FetchDataL - Available certs=%d\n"),
	aAvailableCerts.Count()));
	
	// Loop through available certs
	TInt i(0);
	for (i = 0; i < aAvailableCerts.Count(); i++)
	{
		SCertEntry cert = aAvailableCerts[i];
		
		tmp.iCertEntry = cert;
		tmp.iIsEnabled = EFalse;
		
		// Try to find the cert from the database rows
		if (view.FirstL())
		{
			do 
			{
				view.GetL();
				if ((view.ColDes(colSet->ColNo(KCertLabel)) == cert.iLabel 
					|| view.IsColNull(colSet->ColNo(KCertLabel)))
					&& view.ColDes8(colSet->ColNo(KSubjectKeyIdentifier)) == cert.iSubjectKeyId)
				{
					tmp.iIsEnabled = ETrue;
					
					EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::FetchDataL - Reading certificate details from the DB - Label=%S \n"),
					&(cert.iLabel) ) );
					
					EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "Subject Key Id:", cert.iSubjectKeyId.Ptr(), 
																cert.iSubjectKeyId.Size() ) );					
					break;
				}
			} while (view.NextL() != EFalse);
		}
		
		aArray->AppendL(tmp);
	}
	CleanupStack::PopAndDestroy(); // colset
	CleanupStack::PopAndDestroy(); // view
    CleanupStack::PopAndDestroy(buf);
}

TInt CEapTlsPeapUiCertificates::Update()
{
	TRAPD(err, UpdateL());
	
	if(KErrNone != err)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::Update - UpdateL LEAVES with error =%d \n"),
		err));		
	}

	return err;
}


void CEapTlsPeapUiCertificates::UpdateL()
{
	HBufC* buf = HBufC::NewLC(KMaxSqlQueryLength);
	TPtr sqlStatement = buf->Des();

	// USER CERTIFICATES
	_LIT(KSQL, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	if (iUiConn->GetEapType() == eap_type_tls)
	{
		sqlStatement.Format(
			KSQL, 
			&KTlsAllowedUserCertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}
	else if (iUiConn->GetEapType() == eap_type_peap)
	{
		sqlStatement.Format(
			KSQL, 
			&KPeapAllowedUserCertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}	
	else if (iUiConn->GetEapType() == eap_type_ttls || iUiConn->GetEapType() == eap_type_ttls_plain_pap)
	{
		sqlStatement.Format(
			KSQL, 
			&KTtlsAllowedUserCertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}
	
#ifdef USE_FAST_EAP_TYPE	
	else if (iUiConn->GetEapType() == eap_type_fast)
	{
		sqlStatement.Format(
			KSQL, 
			&KFastAllowedUserCertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}
#endif //#ifdef USE_FAST_EAP_TYPE	

	RDbView view;	
	User::LeaveIfError(view.Prepare(iDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));	
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());

	// Get column set so we get the correct column numbers
	CDbColSet* colSet;
	colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Delete old rows
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL - About to update cert details in the DB - User cert count=%d \n"),
	iUserCerts->Count()));
	
	TInt i(0);
	for (i = 0; i < iUserCerts->Count(); i++)
	{
		if ((*iUserCerts)[i].iIsEnabled)
		{
			// Validate data lengths.
			if((*iUserCerts)[i].iCertEntry.iLabel.Length() > KMaxCertLabelLengthInDB 
				|| (*iUserCerts)[i].iCertEntry.iSubjectKeyId.Length() > KMaxSubjectKeyIdLengthInDB)
			{
				// Too long data. Can not be stored in DB.

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL: User : Too long Label or SubjectKeyId. Length: Label=%d, SubjectKeyId=%d \n"),
				(*iUserCerts)[i].iCertEntry.iLabel.Length(), (*iUserCerts)[i].iCertEntry.iSubjectKeyId.Length()));
								
				User::Leave(KErrArgument);
			}
						
			view.InsertL();
			// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(iUiConn->GetIndexType()));
			view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(iUiConn->GetIndex()));
			view.SetColL(colSet->ColNo(KTunnelingType), static_cast<TUint>(iUiConn->GetTunnelingType()));
			view.SetColL(colSet->ColNo(KCertLabel), (*iUserCerts)[i].iCertEntry.iLabel);
			view.SetColL(colSet->ColNo(KSubjectKeyIdentifier), (*iUserCerts)[i].iCertEntry.iSubjectKeyId);
			view.SetColL(colSet->ColNo(KActualSubjectKeyIdentifier), (*iUserCerts)[i].iCertEntry.iSubjectKeyId);
			view.PutL();
			
			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL - Wrote User cert details to the DB - Label=%S \n"),
			&((*iUserCerts)[i].iCertEntry.iLabel) ) );
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "Subject Key Id:", (*iUserCerts)[i].iCertEntry.iSubjectKeyId.Ptr(), 
			(*iUserCerts)[i].iCertEntry.iSubjectKeyId.Size() ) );			
		}
	}
	
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(); // view	
	
	// CA CERTIFICATES
	_LIT(KSQL2, "SELECT * FROM %S WHERE %S=%d AND %S=%d AND %S=%d");
	
	if (iUiConn->GetEapType() == eap_type_tls)
	{
		sqlStatement.Format(
			KSQL2, 
			&KTlsAllowedCACertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}
	else if (iUiConn->GetEapType() == eap_type_peap)
	{
		sqlStatement.Format(
			KSQL2, 
			&KPeapAllowedCACertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}	
	else if (iUiConn->GetEapType() == eap_type_ttls || iUiConn->GetEapType() == eap_type_ttls_plain_pap)
	{
		sqlStatement.Format(
			KSQL2, 
			&KTtlsAllowedCACertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}

#ifdef USE_FAST_EAP_TYPE
	else if (iUiConn->GetEapType() == eap_type_fast)
	{
		sqlStatement.Format(
			KSQL2, 
			&KFastAllowedCACertsDatabaseTableName, 
			&KServiceType, 
			iUiConn->GetIndexType(), 
			&KServiceIndex,
			iUiConn->GetIndex(), 
			&KTunnelingType, 
			iUiConn->GetTunnelingType());
	}	
#endif // #ifdef USE_FAST_EAP_TYPE	
			
	User::LeaveIfError(view.Prepare(iDatabase, TDbQuery(sqlStatement), TDbWindow::EUnlimited));	
	CleanupClosePushL(view);
	User::LeaveIfError(view.EvaluateAll());

	// Get column set so we get the correct column numbers
	colSet = view.ColSetL();
	CleanupStack::PushL(colSet);

	// Delete old rows
	if (view.FirstL())
	{		
		do {
			view.DeleteL();
		} while (view.NextL() != EFalse);
	}
	
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL - About to update cert details in the DB - CA cert count=%d \n"),
	iCACerts->Count()));
	
	for (i = 0; i < iCACerts->Count(); i++)
	{
		if ((*iCACerts)[i].iIsEnabled)
		{
			// Validate data lengths.
			if((*iCACerts)[i].iCertEntry.iLabel.Length() > KMaxCertLabelLengthInDB 
				|| (*iCACerts)[i].iCertEntry.iSubjectKeyId.Length() > KMaxSubjectKeyIdLengthInDB)
			{
				// Too long data. Can not be stored in DB.

				EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL: CA : Too long Label or SubjectKeyId. Length: Label=%d, SubjectKeyId=%d \n"),
				(*iCACerts)[i].iCertEntry.iLabel.Length(), (*iCACerts)[i].iCertEntry.iSubjectKeyId.Length()));
				
				User::Leave(KErrArgument);
			}
		
			view.InsertL();
			// Set the default values. The other three tables (certs, ca certs & cipher suites) are empty by default.
			view.SetColL(colSet->ColNo(KServiceType), static_cast<TUint>(iUiConn->GetIndexType()));
			view.SetColL(colSet->ColNo(KServiceIndex), static_cast<TUint>(iUiConn->GetIndex()));
			view.SetColL(colSet->ColNo(KTunnelingType), static_cast<TUint>(iUiConn->GetTunnelingType()));
			view.SetColL(colSet->ColNo(KCertLabel), (*iCACerts)[i].iCertEntry.iLabel);
			view.SetColL(colSet->ColNo(KSubjectKeyIdentifier), (*iCACerts)[i].iCertEntry.iSubjectKeyId);			
			view.SetColL(colSet->ColNo(KActualSubjectKeyIdentifier), (*iCACerts)[i].iCertEntry.iSubjectKeyId);
			view.PutL();

			EAP_TRACE_DEBUG_SYMBIAN((_L("CEapTlsPeapUiCertificates::UpdateL - Wrote CA cert details to the DB - Label=%S \n"),
			&((*iCACerts)[i].iCertEntry.iLabel) ) );
			
			EAP_TRACE_DATA_DEBUG_SYMBIAN( ( "Subject Key Id:", (*iCACerts)[i].iCertEntry.iSubjectKeyId.Ptr(), 
			(*iCACerts)[i].iCertEntry.iSubjectKeyId.Size() ) );
		}
	}
	CleanupStack::PopAndDestroy(colSet);
	CleanupStack::PopAndDestroy(); // view
	
	CleanupStack::PopAndDestroy(buf);
}

// End of file
