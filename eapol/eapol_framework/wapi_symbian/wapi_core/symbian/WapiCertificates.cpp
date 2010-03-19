/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wapi_core/symbian/WapiCertificates.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 25.1.3 % << Don't touch! Updated by Synergy at check-out.
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
#include "WapiCertificates.h"
#include "certificate_store_db_symbian.h"
#include "abs_eap_am_tools.h"
#include "eap_am_tools_symbian.h"
#include "dummy_wapi_core.h"
#include "wapi_am_core_symbian.h"
#include "ec_certificate_store.h"
#include <e32std.h>

// -----------------------------------------------------------------------------
// CWapiCertificates::CWapiCertificates()
// The constructor does not do anything
// -----------------------------------------------------------------------------
//
EXPORT_C CWapiCertificates::CWapiCertificates(): CActive(CActive::EPriorityStandard)
    {
    }
    
// -----------------------------------------------------------------------------
// CWapiCertificates::~CWapiCertificates()
// The destructor
// -----------------------------------------------------------------------------
//
EXPORT_C CWapiCertificates::~CWapiCertificates()
    {    
    if ( iEcCertStore != NULL )
        {
        iEcCertStore->shutdown();
        delete iEcCertStore;
        }
    if ( iWapiCore != NULL )
        {
        iWapiCore->shutdown();
        delete iWapiCore;
        }
    delete iCertDB;

    delete iDummyCore;
    
    if ( iAmTools != NULL )
        {
        iAmTools->am_cancel_all_timers();
				abs_eap_am_tools_c::delete_abs_eap_am_tools_c(iAmTools);
        }
    
    if(IsActive())
	    {
	    Cancel();		
	    }
    }
    
// -----------------------------------------------------------------------------
// CWapiCertificates::ConstructL
// Symbian 2nd phase constructor can leave.
// -----------------------------------------------------------------------------
//
void CWapiCertificates::ConstructL()
    {
	  // Create the needed certificate store object
    iAmTools = abs_eap_am_tools_c::new_abs_eap_am_tools_c();
    if ( iAmTools == NULL || iAmTools->get_is_valid() != true )
        {
        User::Leave(KErrGeneral);
        }
    
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CWapiCertificates::ConstructL\n" ) ) );

    iCertDB = CCertificateStoreDatabase::NewL( iAmTools );
    // Open the certificate store connection
    iCertDB->OpenCertificateStoreL();
  
    // create the dummy core and ec cert store in order to create the 
    // wapi_am_core_symbian object
    iDummyCore = new(ELeave) dummy_wapi_core_c();
    // check if dummyCore is ok
    if ( iDummyCore->get_is_valid() == false )
        {
        User::Leave( KErrGeneral );
        }
    
    iWapiCore = wapi_am_core_symbian_c::NewL( iAmTools, iDummyCore, iCertDB, false);
    
    iCertDB->SetCorePartner(iWapiCore);
    
    iEcCertStore = new(ELeave) ec_certificate_store_c(iAmTools, iDummyCore, iWapiCore , true);
    
    eap_status_e status = iEcCertStore->configure();
    if(status != eap_status_ok)
        {
        User::Leave( KErrGeneral );
        }
        
    iWapiCore->set_am_certificate_store_partner(iEcCertStore);
    
    CActiveScheduler::Add(this); // add this object to the active scheduler
  	}

// -----------------------------------------------------------------------------
// CWapiCertificates::NewL
// Two-phased constructor.
// -----------------------------------------------------------------------------
//   
EXPORT_C CWapiCertificates* CWapiCertificates::NewL()
    {
    CWapiCertificates* self = new(ELeave) CWapiCertificates(); 
    CleanupStack::PushL(self);
    self->ConstructL();
    CleanupStack::Pop(self);
    return self;
    }
		

    
//------------------------------------------------------------------------------
// CWapiCertificates::GetAllCertificateLabelsL( )
//------------------------------------------------------------------------------
EXPORT_C void CWapiCertificates::GetAllCertificateLabelsL( RArray<TBuf<KMaxLabelLength> > **aUserCerts, RArray<TBuf8<KMaxIdentityLength> >**aUserCertData,
        RArray<TBuf<KMaxLabelLength> > **aCACerts, RArray<TBuf8<KMaxIdentityLength> >**aCACertData )
    {
    // Use the provided service for reading the list.

    iWapiCore->GetAllCertificateLabelsL( aUserCerts, aCACerts, aUserCertData, aCACertData, iStatus );
    // Let's wait until certificate db get's the job done and return after that
    SetActive();
    iWait.Start();
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CWapiCertificates::GetAllCertificateLabelsL, status = %d.\n" ),
        iStatus.Int() ) );

    if (*aCACerts)
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CWapiCertificates::GetAllCertificateLabelsL, CA Count = %d.\n" ),
                (*aCACerts)->Count() ) );
        }
    if (*aUserCerts)
        {
        EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CWapiCertificates::GetAllCertificateLabelsL, Client count = %d.\n" ),
                (*aUserCerts)->Count() ) );
        }
    
    if (*aCACerts)
        {
        for (TInt aCa = 0; aCa <(*aCACerts)->Count(); aCa++)
            {
            TPtrC certPtr;
            certPtr.Set ((**aCACerts)[aCa]);
            EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "CaCert:"), certPtr.Ptr(),
                certPtr.Size() ));
            }
        }
    
    if (*aUserCerts)
        {
        for (TInt aCa = 0; aCa <(*aUserCerts)->Count(); aCa++)
            {
            TPtrC certPtr;
            certPtr.Set ((**aUserCerts)[aCa]);
            EAP_TRACE_DATA_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
                "ClientCert:"), certPtr.Ptr(),
                certPtr.Size() ));
            }
        }
    // Check the status
    User::LeaveIfError( iStatus.Int() );
    return;
    }
    
//------------------------------------------------------------------------------
// CWapiCertificates::ResetCertificateStore( )
//------------------------------------------------------------------------------
EXPORT_C void CWapiCertificates::ResetCertificateStoreL( )
    {
    // Use the provided service for destroying the certificate store
    TInt error = iCertDB->DestroyCertificateStore( );
    // Leave if error returned
    User::LeaveIfError( error );
    }
    
//------------------------------------------------------------------------------
// CWapiCertificates::GetConfiguration(TInt aId, TDes& aCACert, TDes& aUserCert)
//------------------------------------------------------------------------------
EXPORT_C void CWapiCertificates::GetConfigurationL( const TInt aId, TDes& aCACert, TDes& aUserCert )
    {
    // Use the provided service for getting the selected CA and user certificates
    iCertDB->GetConfigurationL( aId, aCACert, aUserCert );
    }

//------------------------------------------------------------------------------
// CWapiCertificates::SetCACert( TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert )
//------------------------------------------------------------------------------
EXPORT_C void CWapiCertificates::SetCACertL( const TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert )
    {
    // Use the provided service for setting the selected CA certificate
    iCertDB->SetCACertL( aId, aSelectedCert );
    }

//------------------------------------------------------------------------------
// CWapiCertificates::SetUserCert( TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert )
//------------------------------------------------------------------------------
EXPORT_C void CWapiCertificates::SetUserCertL( const TInt aId, const TBuf8<KMaxIdentityLength> aSelectedCert)
    {
    // Use the provided service for setting the selected user certificate
    iCertDB->SetUserCertL( aId, aSelectedCert );
    }

//------------------------------------------------------------------------------
// CWapiCertificates::DeleteAPSpecificDataL( TInt aId )
//------------------------------------------------------------------------------
EXPORT_C void CWapiCertificates::DeleteAPSpecificDataL( const TInt aId )
    {
    // Use the provided service for deleting the rows mathing the id
    iCertDB->DeleteAPSpecificDataL( aId );
    }
    
// ================= protected: from CActive =======================
    
// ---------------------------------------------------------
// CWapiCertificates::RunL()
// ---------------------------------------------------------
//
void CWapiCertificates::RunL()
    {
    EAP_TRACE_DEBUG( iAmTools, TRACE_FLAGS_DEFAULT, ( EAPL(
        "CWapiCertificates::RunL() IN, iStatus=%d.\n"), iStatus.Int() ) );
        
    // This is needed to continue the execution after Wait.Start(); 
    iWait.AsyncStop(); 
    return; 
    } // CWapiCertificates::RunL()

    
// ---------------------------------------------------------
// CWapiCertificates::RunL()
// ---------------------------------------------------------
//
void CWapiCertificates::DoCancel()
    {
    if( iStatus == KRequestPending )
        {
        TRequestStatus * reqStat = &iStatus;
        User::RequestComplete(reqStat, KErrCancel);
        }
    }

// End of file
