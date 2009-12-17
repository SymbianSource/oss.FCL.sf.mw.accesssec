/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  WAPI authentication protocols.
*
*/


#ifndef _WAPICERTIFICATES_H_
#define _WAPICERTIFICATES_H_

#include <e32base.h>
#include <e32std.h>


const TInt KMaxLabelLength = 255;
const TInt KMaxIdentityLength = 310;
class CCertificateStoreDatabase;
class abs_eap_am_tools_c;
class dummy_wapi_core_c;
class wapi_am_core_symbian_c;
class ec_certificate_store_c;

/**
*  This is a wrapper class which can be used to handle WAPI related certificates
*/
class CWapiCertificates : /*public CBase,*/ public CActive
{

public:

    IMPORT_C CWapiCertificates();
    IMPORT_C ~CWapiCertificates();
    
    /**
    * Function for creating the CWapiCertificates object
    *
    */
    IMPORT_C static CWapiCertificates* NewL();
    
     /**
    * Function for reserving memory for the internal data types
    *
    */
    void ConstructL();
    
    /**
    * Gets a list of the available WAPI user and CA certificates
    * 
    * NOTE that the caller is responsible for freeing the memory of the arrays
    *
    * @param aUserCerts Array of available WAPI User certificate labels
    * @param aUserCertData Array of available WAPI User certificate identities
    * @param aCACerts   Array of available WAPI CA certificate labels
    * @param aCACertData   Array of available WAPI CA certificate identities
    */
    IMPORT_C void GetAllCertificateLabelsL( RArray<TBuf<KMaxLabelLength> > **aUserCerts, RArray<TBuf8<KMaxIdentityLength> > **aUserCertData,
            RArray<TBuf<KMaxLabelLength> > **aCACerts, RArray<TBuf8<KMaxIdentityLength> >**aCACertData );
	
    /**
    * Resets the WAPI Certificate store
    *
    */
    IMPORT_C void ResetCertificateStoreL( );
	
    /**
    * Gets the WAPI certificate configuration of a specific AP
    *
    * @param aId        Service table id
    * @param aUserCert  Id matching the selected WAPI User certificate
    * @param aCACert    Id matching the selected WAPI CA certificate
    */
    IMPORT_C void GetConfigurationL( const TInt aId, TDes& aCACert, TDes& aUserCert );
	
    /**
    * Sets the WAPI certificate configuration of a specific AP
    *
    * @param aId          Service table id
    * @param aCACertData  Selected WAPI CA certificate identity 
    */
    IMPORT_C void SetCACertL( const TInt aId, const TBuf8<KMaxIdentityLength> aCACertData );
	
    /**
    * Sets the WAPI certificate configuration of a specific AP
    *
    * @param aId           Service table id
    * @param aUserCertData Selected WAPI User certificate identity 
    */
    IMPORT_C void SetUserCertL( const TInt aId, const TBuf8<KMaxIdentityLength> aUserCertData );
    
    /**
    * Delete AP related data from certificate database tables
    *
    * @param aId        Service table id
    */
    IMPORT_C void DeleteAPSpecificDataL( const TInt aId );
    
protected: // from CActive
    
    /**
    * RunL from CActive
    */    
    void RunL();
    
    /**
    * DoCancel from CActive
    */    
    void DoCancel();
private:
    // Pointer to the used certificate store object
    CCertificateStoreDatabase* iCertDB; 
    // amTools is needed for the certificate store object creation
    abs_eap_am_tools_c* iAmTools;
    dummy_wapi_core_c* iDummyCore;
    // The pointer to the ec_certificate_store_c needed to create the wapi_am_core_symbian
    ec_certificate_store_c* iEcCertStore;
    // The pointer to the object needed to start the certificate import and reading of labels
    wapi_am_core_symbian_c* iWapiCore;
    	
    // For wrapping asynchronous calls.
    CActiveSchedulerWait iWait;
};

#endif // _WAPICERTIFICATES_H_

// End of file
