/*
* ============================================================================
*  Name     : wapisecuritysettingsimpl.cpp 
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Implementation of class CWAPISecuritySettingsImpl.   
*      
*  Version: %version:  13.1.2 %
*
*  Copyright (C) 2008 Nokia Corporation.
*  This material, including documentation and any related 
*  computer programs, is protected by copyright controlled by 
*  Nokia Corporation. All rights are reserved. Copying, 
*  including reproducing, storing,  adapting or translating, any 
*  or all of this material requires the prior written consent of 
*  Nokia Corporation. This material also contains confidential 
*  information which may not be disclosed to others without the 
*  prior written consent of Nokia Corporation.
*
* ============================================================================
*/

// INCLUDE FILES

#include "wapisecuritysettingsimpl.h"
#include "wapisecuritysettingsuipanic.h"
#include "wapisecuritysettingsui.h"

#include <featmgr.h>
#include <cmdestinationext.h>
#include <cmmanagerext.h>

#include <wlancontainer.h>

// CONSTANT DECLARATIONS


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::NewL
// ---------------------------------------------------------
//
CWAPISecuritySettingsImpl* CWAPISecuritySettingsImpl::NewL()
    {
    CWAPISecuritySettingsImpl* settings = 
                                    new ( ELeave ) CWAPISecuritySettingsImpl();
    CleanupStack::PushL( settings );
    settings->ConstructL();
    CleanupStack::Pop( settings ); 
    return settings;    
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::CWAPISecuritySettingsImpl
// ---------------------------------------------------------
//
CWAPISecuritySettingsImpl::CWAPISecuritySettingsImpl()
    {
    iUserCertInUse = KCertNone;
    iCACertInUse = KCertNone;
    iCertificatesLoaded = EFalse;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::ConstructL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::ConstructL()
    {
    iCertificateStore =  CWapiCertificates::NewL(); 
    
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsImpl::ConstructL, iCertificateStore created.") );
    #endif

    FeatureManager::InitializeLibL();
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::~CWAPISecuritySettingsImpl
// ---------------------------------------------------------
//
CWAPISecuritySettingsImpl::~CWAPISecuritySettingsImpl()
    {
    if (iUserCertificates)
        {
        iUserCertificates->Close();
        delete iUserCertificates;
        }
    if (iUserCertificateData)
        {
        iUserCertificateData->Close();
        delete iUserCertificateData;
        }

    if (iCACertificates)
       {
       iCACertificates->Close();
       delete iCACertificates;
       }
    if (iCACertificateData)
        {
        iCACertificateData->Close();
        delete iCACertificateData;
        }

    delete iCertificateStore;

    FeatureManager::UnInitializeLib();
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::LoadL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::LoadL( TUint32 aIapRecordId, CMDBSession& aSession )
    {
    CCDIAPRecord *iapRecord = static_cast<CCDIAPRecord *>
                            (CCDRecordBase::RecordFactoryL(KCDTIdIAPRecord));
                            
    CleanupStack::PushL( iapRecord );
    
    iapRecord->SetRecordId( aIapRecordId );
    
    iapRecord->LoadL( aSession );
    
    TUint32 wlanServiceId = iapRecord->iService;
    
    CleanupStack::PopAndDestroy(iapRecord);
    
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsImpl::LoadL, aIapId = %d, wlanServiceId = %d"),
            aIapRecordId, wlanServiceId );
    #endif
    
    if ( wlanServiceId == KUidNone )
        {
        return;
        }
    
    // search for the record    
    CMDBGenericRecord* generic = static_cast<CMDBGenericRecord*>( 
                                          CCDRecordBase::RecordFactoryL( 0 ) );
    CleanupStack::PushL( generic );    
    generic->InitializeL( TPtrC( WLAN_SERVICE ), NULL );
    generic->LoadL( aSession );
    
    CMDBField<TUint32>* sidField = static_cast<CMDBField<TUint32>*>
                             ( generic->GetFieldByIdL( KCDTIdWlanServiceId ) );
    
    // prime with service id                
    *sidField = wlanServiceId;
    
    if (generic->FindL( aSession ))
        {
        // Get authentication
        CMDBField<TUint>* enableWpaPskField = static_cast<CMDBField<TUint>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanEnableWpaPsk ) );
        iWapiAuth = (*enableWpaPskField == 0 ) ? EWapiAuthCert : EWapiAuthPSK;

        // Get preshared key format
        CMDBField<CWAPISecuritySettings::TWapiKeyFormat>* wapiPskFormat = static_cast<CMDBField<CWAPISecuritySettings::TWapiKeyFormat>*>
                       ( generic->GetFieldByIdL( KCDTIdWlanFormatKey1 ) );
        iWapiKeyFormat = *wapiPskFormat;

        // Get preshared key
        CMDBField<TDesC8>* wpaPskField = static_cast<CMDBField<TDesC8>*>
                       ( generic->GetFieldByIdL( KCDTIdWlanWpaPreSharedKey ) );
        iWapiPSKKey = *wpaPskField;
        
        iWapiPSKKeySet = IsValidPsk(iWapiPSKKey);
        }
   
    // Save aIapRecordId for later certificate loading.
    iWlanServiceId = wlanServiceId;
    
    CleanupStack::PopAndDestroy( generic );
   
    }
    

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SaveL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::SaveL( TUint32 aIapRecordId, CMDBSession& aSession  ) const
    {

    CCDIAPRecord *iapRecord = static_cast<CCDIAPRecord *>
                            (CCDRecordBase::RecordFactoryL(KCDTIdIAPRecord));
                            
    CleanupStack::PushL( iapRecord );
    
    iapRecord->SetRecordId( aIapRecordId );
    
    iapRecord->LoadL( aSession );
    
    TUint32 wlanServiceId = iapRecord->iService;

    CleanupStack::PopAndDestroy(iapRecord);   
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsImpl::SaveL, iapRecordId = %d, wlanServiceId = %d"),
            aIapRecordId, wlanServiceId );
    #endif

    // Load WLAN service table
    // first get WLAN table id
    CMDBGenericRecord* generic = static_cast<CMDBGenericRecord*>
        ( CCDRecordBase::RecordFactoryL( 0 ) );
    CleanupStack::PushL( generic );    
    generic->InitializeL( TPtrC( WLAN_SERVICE ), NULL );
    generic->LoadL( aSession );
    TMDBElementId wlanTableId = generic->TableId();
    
    CMDBField<TUint32>* sidField = static_cast<CMDBField<TUint32>*>
                             ( generic->GetFieldByIdL( KCDTIdWlanServiceId ) );
    
    // prime with service id                
    *sidField = wlanServiceId;

    TBool found = generic->FindL( aSession);
   
    // If loading failed, WLAN service record will be 
    // created and StoreL()-d, otherwise, ModifyL()
    
    // Set WPA mode
    CMDBField<TUint>* enableWpaPskField = static_cast<CMDBField<TUint>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanEnableWpaPsk ) );
    enableWpaPskField->SetL( iWapiAuth == EWapiAuthPSK ? 1 : 0 );
    
    if (iWapiAuth == EWapiAuthPSK)
        {
        if (iWapiPSKKeySet)
            {

            // Save PreShared Key format
            CMDBField<TUint>* keyFormat = static_cast<CMDBField<TUint>*>
                                ( generic->GetFieldByIdL( KCDTIdWlanFormatKey1 ) );
            keyFormat->SetL( iWapiKeyFormat );
            
            // Save PreShared Key
            CMDBField<TDesC8>* wapiPskField = static_cast<CMDBField<TDesC8>*>
                               ( generic->GetFieldByIdL( KCDTIdWlanWpaPreSharedKey ) );
            wapiPskField->SetL( iWapiPSKKey );
    
            // Save PreShared Key length
            CMDBField<TUint>* keyLengthField = static_cast<CMDBField<TUint>*>
                                ( generic->GetFieldByIdL( KCDTIdWlanWpaKeyLength ) );
            keyLengthField->SetL( iWapiPSKKey.Length() );
            }
        }
    // If certificates have not been loaded, i*CertInUse doesn't contain right values
    else if ( iCertificateStore && iCertificatesLoaded != EFalse)
        {
        #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("Saving user cert index %d"), iUserCertInUse );
        RDebug::Print(_L("Saving CA cert index %d"), iCACertInUse );
        #endif  
        
        // "none" is communicated to wapicertificates as zero length identity
        TBuf8<KMaxIdentityLength> certNone;
        certNone.Zero();

        if (iUserCertInUse == KCertNone)
            {
            iCertificateStore->SetUserCertL( wlanServiceId, certNone);
            }
        else
            {
            iCertificateStore->SetUserCertL( wlanServiceId, (*iUserCertificateData)[iUserCertInUse]);
            }
         
        if (iCACertInUse == KCertNone)
            {
            iCertificateStore->SetCACertL( wlanServiceId, certNone);
            }
        else
            {
            iCertificateStore->SetCACertL( wlanServiceId, (*iCACertificateData)[iCACertInUse]);
            }
        }
    // Saving changes
    if ( !found )
        {
        // there wasn't any wlan service record, we have to create it now
        generic->SetRecordId( KCDNewRecordRequest );
        generic->StoreL( aSession );
        }
    else
        {
        // modify existing record
        generic->ModifyL( aSession );
        }
        
    CleanupStack::PopAndDestroy( generic );
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SetPreSharedKeyL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::SetPreSharedKeyL( const CWAPISecuritySettings::TWapiKeyFormat aKeyFormat, const TDesC& aPreSharedKey )
    {
    HBufC8* buf8 = HBufC8::NewL( aPreSharedKey.Length() );
    
    TPtr8 pskPtr( buf8->Des() );
    pskPtr.Copy( aPreSharedKey ); 

    if ( !IsValidPsk( aKeyFormat, pskPtr ) )
        {
        delete buf8;
        User::Leave(KErrArgument);
        }
    
    SetAuthentication(EWapiAuthPSK);
    SetKeyFormat( aKeyFormat );
    SetWapiPSKKeyL( aPreSharedKey );

    delete buf8;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::ResetCertificateStoreL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::ResetCertificateStoreL()
    {
    if ( iCertificateStore )
        {
        iCertificateStore->ResetCertificateStoreL();
            
        //Certificate store was reseted. Set certificates in use to "None" and
        //Close RARRAY's
        iUserCertInUse = KCertNone;
        iCACertInUse = KCertNone;

        // Reload certificate data: delete old and load new ones.
        if (iUserCertificates)
            {
            iUserCertificates->Close();
            delete iUserCertificates;
            iUserCertificates = NULL;
            }
        if (iUserCertificateData)
            {
            iUserCertificateData->Close();
            delete iUserCertificateData;
            iUserCertificateData = NULL;
            }
        
        if (iCACertificates)
            {
            iCACertificates->Close();
            delete iCACertificates;
            iCACertificates = NULL;
            }
        if (iCACertificateData)
            {
            iCACertificateData->Close();
            delete iCACertificateData;
            iCACertificateData = NULL;
            }
        
        iCertificateStore->GetAllCertificateLabelsL(
                &iUserCertificates, &iUserCertificateData,
                &iCACertificates, &iCACertificateData);
        }
    }
// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::LoadCertificatesL
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::LoadCertificatesL()
    {
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("LoadCertificatesL()"));
    #endif

    if ( iCertificateStore && iCertificatesLoaded == EFalse)
        {
        iCertificateStore->GetAllCertificateLabelsL(
                &iUserCertificates, &iUserCertificateData,
                &iCACertificates, &iCACertificateData);
       
        //Define local variables for certificate labels
        TBuf<KMaxLabelLength>               userCertLabel;
        TBuf<KMaxLabelLength>               CACertLabel;
        
        //Fetch configuration from EAPOL
        iCertificateStore->GetConfigurationL( 
                                    iWlanServiceId, CACertLabel, userCertLabel );
    
        #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("CWAPISecuritySettingsImpl::LoadL, iWlanServiceId = %d"), iWlanServiceId );
        RDebug::Print(_L("CWAPISecuritySettingsImpl::LoadL, CACertLabel = %S"), &CACertLabel );
        RDebug::Print(_L("CWAPISecuritySettingsImpl::LoadL, userCertLabel = %S"), &userCertLabel );
        #endif
    
        //Fetch matching indexes
        iUserCertInUse = GetIndexByCertLabel(iUserCertificates, userCertLabel);
        iCACertInUse = GetIndexByCertLabel(iCACertificates, CACertLabel);
        
        #if defined( _DEBUG ) || defined( DEBUG )
        RDebug::Print(_L("iUserCertInUse = %d"), iUserCertInUse );
        RDebug::Print(_L("iCACertInUse = %d"), iCACertInUse );
        #endif
        
        // Don't load certificates again because it resets made configuration changes too.
        iCertificatesLoaded = ETrue;
        }
    }


//------------------------------------------------------------------------------
// CWAPISecuritySettingsImpl::DeleteAPSpecificDataL
//------------------------------------------------------------------------------
//
void CWAPISecuritySettingsImpl::DeleteAPSpecificDataL( const TInt aId )
    {
    if ( iCertificateStore )
        {
        iCertificateStore->DeleteAPSpecificDataL( aId );
        }
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetIndexByCertLabel
// ---------------------------------------------------------
//
TInt CWAPISecuritySettingsImpl::GetIndexByCertLabel( 
                            RArray<TBuf<KMaxLabelLength> >* aCertificates, 
                            const TDesC& aCert )
    {
    if ( aCertificates )
        {
        for ( TInt i = 0; i < aCertificates->Count(); i++ )
            {
            if ( aCert.Compare((*aCertificates)[i])== 0 ) //Compare returns zero
                                                        //when result is matching
                {
                return i;
                }
            }
        }
    return KCertNone; // if certificate is not found return zero index
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetAuthentication
// ---------------------------------------------------------
//
TWapiAuth CWAPISecuritySettingsImpl::GetAuthentication( )
    {
    return iWapiAuth;
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SetAuthentication
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::SetAuthentication( TWapiAuth aWapiAuth )
    {
    iWapiAuth = aWapiAuth;
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetKeyFormat
// ---------------------------------------------------------
//
CWAPISecuritySettings::TWapiKeyFormat CWAPISecuritySettingsImpl::GetKeyFormat()
    {
    return iWapiKeyFormat;
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SetKeyFormat
// ---------------------------------------------------------
//
void CWAPISecuritySettingsImpl::SetKeyFormat( CWAPISecuritySettings::TWapiKeyFormat aWapiKeyFormat )
    {
    iWapiKeyFormat = aWapiKeyFormat;
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetWapiPSKKey
// ---------------------------------------------------------
//
TBool CWAPISecuritySettingsImpl::hasWapiPSKKey()
    {
    return iWapiPSKKeySet;
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SetWapiPSKKey
// ---------------------------------------------------------
//
TInt CWAPISecuritySettingsImpl::SetWapiPSKKeyL( const TDesC& aWapiPSKKey )
    {
    TInt ret( KErrNone );
    
    #if defined( _DEBUG ) || defined( DEBUG )
    RDebug::Print(_L("CWAPISecuritySettingsImpl::SetWapiPSKKeyL te"));
    #endif
    
    HBufC8* buf8 = HBufC8::NewL( aWapiPSKKey.Length() );
    
    if ( buf8 )
        {
        TPtr8 pskPtr( buf8->Des() );
        pskPtr.Copy( aWapiPSKKey ); 

        if (IsValidPsk(pskPtr))
            {
            iWapiPSKKeySet = ETrue;
            iWapiPSKKey = pskPtr;
            iWapiAuth = EWapiAuthPSK;
            }
        else
            {
            ret = KErrArgument;
            }
        delete buf8;
        }
    else
        {
        ret = KErrNoMemory;
        }
    
    return ret;
    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::IsValidPsk
// ---------------------------------------------------------
//
TBool CWAPISecuritySettingsImpl::IsValidPsk( const TDesC8& aPsk )
    {
    return IsValidPsk(iWapiKeyFormat, aPsk);
    }

TBool CWAPISecuritySettingsImpl::IsValidPsk(
        const CWAPISecuritySettings::TWapiKeyFormat aWapiKeyFormat,
        const TDesC8& aPsk )
    {
    TBool ret( EFalse );
    
    TInt len = aPsk.Length();
    ret = (len >= 1 && len <= KWapiMaxKeyLength );
    
    if (ret && (aWapiKeyFormat == CWAPISecuritySettings::EWapiKeyHex))
        {
        ret = !(len % 2);   // Must be even length
        if (ret)
            {
            // Check contents
            for ( TInt i = 0; i < len; ++i )
                {
                TChar ch( aPsk[i] );
                if ( !ch.IsHexDigit() )
                    {
                    // Got a bad character
                    ret = EFalse;
                    break;
                    }
                }
            }
        }
    
    return ret;

    }

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::Valid
// ---------------------------------------------------------
//
TBool CWAPISecuritySettingsImpl::IsValid( )
    {
    TBool ret( EFalse );

    if (iWapiAuth == EWapiAuthPSK)
        {
        // Pre-shared key is compulsory.
        ret = iWapiPSKKeySet;
        }
    else // ... == EWapiAuthCert
        {
        // Always valid.
        ret = ETrue;
        }
    return ret;
    }

// End of File
