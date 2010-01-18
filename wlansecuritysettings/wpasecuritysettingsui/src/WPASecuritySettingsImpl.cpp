/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Implementation of class CWPASecuritySettingsImpl.     
*
*/

/*
* %version: tr1cfwln#27 %
*/

// INCLUDE FILES

#include "WPASecuritySettingsUiPanic.h"

#include "WPASecuritySettingsUI.hrh"

#include <WPASecuritySettingsUI.h>
#include <commdb.h>
#include <EAPPluginConfigurationIf.h>
#include "WPASecuritySettingsImpl.h"

#include <commsdattypesv1_1.h>
#include <cmmanagertablefields.h>
#include <wlancontainer.h>


// CONSTANTS
LOCAL_D const TUint32 KUidNone = 0;     // Invalid id
LOCAL_D const TUint32 E8021X = 4;       // 802.1X security mode
LOCAL_D const TUint32 EWpa = 8;         // Wpa security mode
LOCAL_D const TUint32 EWpa2 = 16;       // Wpa2 only security mode

LOCAL_D const TUint32 KExpEapTypeLength = 8;    // expanded EAP type length

// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettingsImpl::NewL
// ---------------------------------------------------------
//
CWPASecuritySettingsImpl* CWPASecuritySettingsImpl::NewL( 
                                                TSecurityMode aSecurityMode )
    {
    CWPASecuritySettingsImpl* settings = new ( ELeave ) 
                                    CWPASecuritySettingsImpl( aSecurityMode );
    CleanupStack::PushL( settings );
    settings->ConstructL();
    CleanupStack::Pop( settings ); 
    return settings;    
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::CWPASecuritySettingsImpl
// ---------------------------------------------------------
//
CWPASecuritySettingsImpl::CWPASecuritySettingsImpl( 
                                                TSecurityMode aSecurityMode )
: iSecurityMode( aSecurityMode ),
  iWPAMode( EFalse ),
  iWpa2Only( EFalse )
    {
    iWPAEAPPlugin.Zero();
    iWPAPreSharedKey.Zero();
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::ConstructL
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::ConstructL()
    {
    _LIT8( KMatchString, "EAPPConfig" );
	TRAPD( err, iPlugin = CEAPPluginConfigurationIf::NewL( KMatchString ) );
    if ( err != KErrNone && err != KEComErrNoInterfaceIdentified )
        {
        User::Leave( err );
        }
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::~CWPASecuritySettingsImpl
// ---------------------------------------------------------
//
CWPASecuritySettingsImpl::~CWPASecuritySettingsImpl()
    {
    delete iWPAEnabledEAPPlugin;
    delete iWPADisabledEAPPlugin;
    delete iPlugin;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::LoadL
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::LoadL( TUint32 aIapId, 
                                      CCommsDatabase& aCommsDb )
    {
    if ( aIapId == KUidNone )
        {
        return;
        }

    CCommsDbTableView* wLanServiceTable;
        
    wLanServiceTable = aCommsDb.OpenViewMatchingUintLC(
                    TPtrC( WLAN_SERVICE ), TPtrC( WLAN_SERVICE_ID ), aIapId );

    TInt errorCode = wLanServiceTable->GotoFirstRecord();
    if ( errorCode == KErrNone )
        {
        // Get WPA Mode
        TRAPD( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_ENABLE_WPA_PSK ),
                                                ( TUint32& ) iWPAMode ) );
        if ( err != KErrNone )
            { // do not leave if value is not present in table...
            if ( err != KErrUnknown )
                User::Leave( err );
            }

        TUint32 secMode = 0;
        // Get WPA2 Only Mode
        TRAP( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_SECURITY_MODE ),
                                                 secMode ) );
        if ( err != KErrNone )
            { // do not leave if value is not present in table...
            if ( err != KErrUnknown )
                User::Leave( err );
            }

        iWpa2Only = secMode == EWpa2;

        // Get EAP list
    	iWPAEAPPlugin.Copy( *wLanServiceTable->ReadLongTextLC( 
                                                        TPtrC( WLAN_EAPS ) ) );
	    CleanupStack::PopAndDestroy();
	    
	    if ( !iWPAEAPPlugin.Length() )
	        {
	        // no data found in the old column, use the new ones

	        // enabled EAP types
	        HBufC *data = wLanServiceTable->ReadLongTextLC( 
	                                              TPtrC( WLAN_ENABLED_EAPS ) );

            TPtrC8 reint( reinterpret_cast<const TUint8*>( data->Ptr() ), 
	                                                       data->Size() );
            
        	delete iWPAEnabledEAPPlugin; iWPAEnabledEAPPlugin = NULL;
        	iWPAEnabledEAPPlugin = reint.AllocL();

            CleanupStack::PopAndDestroy( data );
            
            
            // 2. disabled EAP types
            data = wLanServiceTable->ReadLongTextLC( 
	                                             TPtrC( WLAN_DISABLED_EAPS ) );
            
            reint.Set( reinterpret_cast<const TUint8*>( data->Ptr() ), 
	                                                    data->Size() );
	                                                    
        	delete iWPADisabledEAPPlugin; iWPADisabledEAPPlugin = NULL;
        	iWPADisabledEAPPlugin = reint.AllocL();

	        CleanupStack::PopAndDestroy( data );
	        }
	    else
	        {
	        // generate appropriate entries in the new enabled and disabled list,
	        // overwriting those values 
	        
	        // count the + and - signs to determine the size of enabled and 
	        // disabled descriptors
	        TLex lex( iWPAEAPPlugin );
            
	        TInt numPlus = 0;
	        TInt numMinus = 0;
	        TChar ch;
	        while ( !lex.Eos() )
	            {
	            ch = lex.Get();
	            if ( ch == '+' ) ++numPlus;
	            else if ( ch == '-' ) ++numMinus;
	            }
	            
            // each entry consumes 8 bytes in binary format
            delete iWPAEnabledEAPPlugin; iWPAEnabledEAPPlugin = NULL;
            iWPAEnabledEAPPlugin = HBufC8::NewL( 8 * numPlus );
            
            delete iWPADisabledEAPPlugin; iWPADisabledEAPPlugin = NULL;
            iWPADisabledEAPPlugin = HBufC8::NewL( 8 * numMinus );

            lex.Assign( iWPAEAPPlugin );
            
            while ( !lex.Eos() )
                {
                // beginning of implementation UID
                TInt16 implUid = 0;
                
                if ( lex.Val( implUid ) != KErrNone || !implUid )
                    {
                    // if the old string is corrupted, null out both lists
                    iWPAEnabledEAPPlugin->Des().Zero();
                    iWPADisabledEAPPlugin->Des().Zero();
                    break;
                    }

                // append it to the appropriate list ('+' enabled, '-' disabled)
                _LIT8( KPadding, "\xFE\0\0\0\0\0\0" );
                _LIT8( KMsChapV2Padding, "\xFE\xFF\xFF\xFF\0\0\0");
                const TInt KPlainMsChapV2ImplUid = 99;
                
                if ( implUid > 0 )
                    {
                    iWPAEnabledEAPPlugin->Des().Append( 
                                        Abs( implUid ) == KPlainMsChapV2ImplUid? 
                                                    KMsChapV2Padding: KPadding );
                    iWPAEnabledEAPPlugin->Des().Append( Abs( implUid ) );
                    }
                else if (implUid < 0 )
                    {
                    iWPADisabledEAPPlugin->Des().Append( 
                                        Abs( implUid ) == KPlainMsChapV2ImplUid? 
                                                    KMsChapV2Padding: KPadding );
                    iWPADisabledEAPPlugin->Des().Append( Abs( implUid ) );
                    }
                
                // swallow the delimiter (',')
                lex.Get();
                }
                
            // finally, wipe old column data
            iWPAEAPPlugin.Zero();
	        }
	        
        // Get PreShared Key
        wLanServiceTable->ReadTextL( TPtrC( WLAN_WPA_PRE_SHARED_KEY ), 
                                    iWPAPreSharedKey );

        if ( !IsValidPsk( iWPAPreSharedKey ) )
            {       
            // invalid key format
            iWPAPreSharedKey.Zero();
            }
        }

    CleanupStack::PopAndDestroy( wLanServiceTable );  // wLanServiceTable
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SaveL
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::SaveL( TUint32 aIapId, 
                                      CCommsDatabase& aCommsDb,
                                      TTypeOfSaving aTypeOfSaving,
                                      TUint32 aOldIapId )
    {
    CCommsDbTableView* wLanServiceTable;

    // Caller MUST initiate a transaction, WE WILL NOT.

    wLanServiceTable = aCommsDb.OpenViewMatchingUintLC( 
                    TPtrC( WLAN_SERVICE ), TPtrC( WLAN_SERVICE_ID ), aIapId );
    TInt errorCode = wLanServiceTable->GotoFirstRecord();

    if ( errorCode == KErrNone )
        {
        wLanServiceTable->UpdateRecord();
        }
    else
        {
        TUint32 dummyUid( KUidNone );
        User::LeaveIfError( wLanServiceTable->InsertRecord( dummyUid ) );

        // Save link to LAN service
        wLanServiceTable->WriteUintL( TPtrC( WLAN_SERVICE_ID ), aIapId );
        }

    // Save WPA Mode
    wLanServiceTable->WriteUintL( TPtrC( WLAN_ENABLE_WPA_PSK ), 
                                  ( TUint32& ) iWPAMode );

    TUint32 secMode;

    if ( iSecurityMode == ESecurityMode8021x )
        {
        secMode = E8021X;
        }
    else if ( iWpa2Only )
        {
        secMode = EWpa2;
        }
    else
        {
        secMode = EWpa;
        }

    // Save security mode
    wLanServiceTable->WriteUintL( TPtrC( WLAN_SECURITY_MODE ), secMode );

    // With expanded EAP types allowed we no longer need the old column
    iWPAEAPPlugin.Zero(); 

    // Save EAP list
    wLanServiceTable->WriteLongTextL( TPtrC( WLAN_EAPS ), iWPAEAPPlugin );


    // Save the expanded EAPs
    wLanServiceTable->WriteTextL( TPtrC( WLAN_ENABLED_EAPS ), 
                                  iWPAEnabledEAPPlugin? 
                                        (const TDesC8&)*iWPAEnabledEAPPlugin: 
                                        (const TDesC8&)KNullDesC8 );

    wLanServiceTable->WriteTextL( TPtrC( WLAN_DISABLED_EAPS ), 
                                  iWPADisabledEAPPlugin? 
                                        (const TDesC8&)*iWPADisabledEAPPlugin: 
                                        (const TDesC8&)KNullDesC8 );
    // Save PreShared Key
    wLanServiceTable->WriteTextL( TPtrC( WLAN_WPA_PRE_SHARED_KEY ), 
                                  iWPAPreSharedKey );

    // Save PreShared Key Length
    wLanServiceTable->WriteUintL( TPtrC( WLAN_WPA_KEY_LENGTH ), 
                                  iWPAPreSharedKey.Length() );

    wLanServiceTable->PutRecordChanges();

    if ( iPlugin )
        {
        if ( aTypeOfSaving == ESavingBrandNewAP )
            {
            iPlugin->ChangeIapIDL( aOldIapId, aIapId );
            }
        else if ( aTypeOfSaving == ESavingNewAPAsACopy )
            {
            iPlugin->CopySettingsL( aOldIapId, aIapId );
            }
        }

    CleanupStack::PopAndDestroy( wLanServiceTable );  // wLanServiceTable
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::DeleteL
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::DeleteL( TUint32 aIapId )
    {
    if ( iPlugin )
        {
        iPlugin->DeleteSettingsL( aIapId );
        }
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::IsValid
// ---------------------------------------------------------
//
TBool CWPASecuritySettingsImpl::IsValid()
    {
    TBool retval = ETrue;
    if ( iWPAMode || !iPlugin )
        {
        retval = IsValidPsk( iWPAPreSharedKey );
        }

    return retval;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::IsValidPsk
// ---------------------------------------------------------
//
TBool CWPASecuritySettingsImpl::IsValidPsk( const TDesC8& aPsk )
    {
    TBool ret( EFalse );

    TInt len = aPsk.Length();
    
    ret = ( len >= EMinLengthOfPreSharedKeyAscii && 
            len <= EMaxLengthOfPreSharedKeyAscii );
               
    if ( !ret && len == ELengthOfPreSharedKeyHex )
        {
        // perhaps it is hex
        ret = ETrue;
        
        for ( TInt i = 0; i < len; ++i )
            {
            TChar ch( aPsk[i] );
            if ( !ch.IsHexDigit() )
                {
                // got a bad character
                ret = EFalse;
                break;
                }
            }
        }
    
    return ret;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetWPAPreSharedKey
// ---------------------------------------------------------
//
TInt CWPASecuritySettingsImpl::SetWPAPreSharedKey( 
                                                const TDesC& aPreSharedKey )
    {
    TInt ret( KErrNone );
    
    HBufC8* buf8 = HBufC8::New( aPreSharedKey.Length() );
    
    if ( buf8 )
        {
        TPtr8 pskPtr( buf8->Des() );
        pskPtr.Copy( aPreSharedKey ); 

        if ( IsValidPsk( pskPtr ) )
            {
            SetWPAPreSharedKey( pskPtr );
            SetWPAMode( ETrue );
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
// CWPASecuritySettingsImpl::SetWPAEnabledEAPPlugin
// ---------------------------------------------------------
//
TInt CWPASecuritySettingsImpl::SetWPAEnabledEAPPlugin( 
                                             const TDesC8& aEnabledPluginList )
	{
	delete iWPAEnabledEAPPlugin; iWPAEnabledEAPPlugin = NULL;

    if ( aEnabledPluginList.Length() % KExpEapTypeLength )
        {
        // valid expanded EAP types occupy 8 bytes each
        return KErrArgument;
        }

	if ( aEnabledPluginList.Length() )
	    {
	    iWPAEnabledEAPPlugin = aEnabledPluginList.Alloc();
	    if ( !iWPAEnabledEAPPlugin )
	        {
	        return KErrNoMemory;
	        }
	    }
	
	return KErrNone;
	}


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetWPADisabledEAPPlugin
// ---------------------------------------------------------
//
TInt CWPASecuritySettingsImpl::SetWPADisabledEAPPlugin( 
                                            const TDesC8& aDisabledPluginList )
	{
	delete iWPADisabledEAPPlugin; iWPADisabledEAPPlugin = NULL;

    if ( aDisabledPluginList.Length() % KExpEapTypeLength )
        {
        // valid expanded EAP types occupy 8 bytes each
        return KErrArgument;
        }
        
	if ( aDisabledPluginList.Length() )
	    {
	    iWPADisabledEAPPlugin = aDisabledPluginList.Alloc();
	    if ( !iWPADisabledEAPPlugin )
	        {
	        return KErrNoMemory;
	        }
	    }
	
	return KErrNone;
	}
	

// ---------------------------------------------------------
// CWPASecuritySettingsImpl::LoadL
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::LoadL( TUint32 aIapId, 
                                      CMDBSession& aSession )
    {
    if ( aIapId == KUidNone )
        {
        return;
        }
        
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
    *sidField = aIapId;

    if( generic->FindL( aSession) )
        {
        // Get WPA mode
        CMDBField<TUint>* enableWpaPskField = static_cast<CMDBField<TUint>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanEnableWpaPsk ) );
        iWPAMode = *enableWpaPskField;
        
        // Get WPA2 Only Mode
        CMDBField<TUint>* secModeField = static_cast<CMDBField<TUint>*>
                               ( generic->GetFieldByIdL( KCDTIdWlanSecMode ) );
        TUint32 secMode = *secModeField;
        iWpa2Only = secMode == EWpa2;
        
        // Get EAP plugins
        CMDBField<TDesC>* wlanEapsField = static_cast<CMDBField<TDesC>*>
                                  ( generic->GetFieldByIdL( KCDTIdWlanEaps ) );
        iWPAEAPPlugin = *wlanEapsField;
        
	    if ( !iWPAEAPPlugin.Length() )
	        {
	        // no data found in the old column, use the new ones

	        // enabled EAP types
            CMDBField<TDesC8>* wlanEnabledEapsField = 
                          static_cast<CMDBField<TDesC8>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanEnabledEaps ) );

        	delete iWPAEnabledEAPPlugin; iWPAEnabledEAPPlugin = NULL;
        	iWPAEnabledEAPPlugin = 
        	             ( ( const TDesC8& ) *wlanEnabledEapsField ).AllocL();

            
            // disabled EAP types
            CMDBField<TDesC8>* wlanDisabledEapsField = 
                          static_cast<CMDBField<TDesC8>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanDisabledEaps ) );
            
        	delete iWPADisabledEAPPlugin; iWPADisabledEAPPlugin = NULL;
        	iWPADisabledEAPPlugin = 
        	             ( ( const TDesC8& ) *wlanDisabledEapsField ).AllocL();

	        }
	    else
	        {
	        // generate appropriate entries in the new enabled and disabled list,
	        // overwriting those values 
	        
	        // count the + and - signs to determine the size of enabled and 
	        // disabled descriptors
	        TLex lex( iWPAEAPPlugin );
            
	        TInt numPlus = 0;
	        TInt numMinus = 0;
	        TChar ch;
	        while ( !lex.Eos() )
	            {
	            ch = lex.Get();
	            if ( ch == '+' ) ++numPlus;
	            else if ( ch == '-' ) ++numMinus;
	            }
	            
            // each entry consumes 8 bytes in binary format
            delete iWPAEnabledEAPPlugin; iWPAEnabledEAPPlugin = NULL;
            iWPAEnabledEAPPlugin = HBufC8::NewL( 8 * numPlus );
            
            delete iWPADisabledEAPPlugin; iWPADisabledEAPPlugin = NULL;
            iWPADisabledEAPPlugin = HBufC8::NewL( 8 * numMinus );

            lex.Assign( iWPAEAPPlugin );
            
            while ( !lex.Eos() )
                {
                // beginning of implementation UID
                TInt16 implUid = 0;
                
                if ( lex.Val( implUid ) != KErrNone || !implUid )
                    {
                    // if the old string is corrupted, null out both lists
                    iWPAEnabledEAPPlugin->Des().Zero();
                    iWPADisabledEAPPlugin->Des().Zero();
                    break;
                    }

                // append it to the appropriate list ('+' enabled, '-' disabled)
                _LIT8( KPadding, "\xFE\0\0\0\0\0\0" );
                _LIT8( KMsChapV2Padding, "\xFE\xFF\xFF\xFF\0\0\0");
                const TInt KPlainMsChapV2ImplUid = 99;
                
                if ( implUid > 0 )
                    {
                    iWPAEnabledEAPPlugin->Des().Append( 
                                        Abs( implUid ) == KPlainMsChapV2ImplUid? 
                                                    KMsChapV2Padding: KPadding );
                    iWPAEnabledEAPPlugin->Des().Append( Abs( implUid ) );
                    }
                else if (implUid < 0 )
                    {
                    iWPADisabledEAPPlugin->Des().Append( 
                                        Abs( implUid ) == KPlainMsChapV2ImplUid? 
                                                    KMsChapV2Padding: KPadding );
                    iWPADisabledEAPPlugin->Des().Append( Abs( implUid ) );
                    }
                
                // swallow the delimiter (',')
                lex.Get();
                }
                
            // finally, wipe old column data
            iWPAEAPPlugin.Zero();
	        }

        // GetWPA preshared key
        CMDBField<TDesC8>* wpaPskField = static_cast<CMDBField<TDesC8>*>
                       ( generic->GetFieldByIdL( KCDTIdWlanWpaPreSharedKey ) );
        iWPAPreSharedKey = *wpaPskField;
        
        if ( !IsValidPsk( iWPAPreSharedKey ) )
            {       
            // invalid key format
            iWPAPreSharedKey.Zero();
            }
        }
    
    CleanupStack::PopAndDestroy( generic );
    }
    
    
// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SaveL
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::SaveL( TUint32 aIapId, 
                                      CMDBSession& aSession,
                                      TTypeOfSaving aTypeOfSaving,
                                      TUint32 aOldIapId )
    {
    const TInt KRetryWait = 100000;    // Wait time between retries in TTimeIntervalMicroSeconds32
    const TInt KRetryCount = 50;       // Max retry count

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
    *sidField = aIapId;
    
    TBool found = generic->FindL( aSession);
   
    // If loading failed, WLAN service record will be 
    // created and StoreL()-d, otherwise, ModifyL()
    
    // Set WPA mode
    CMDBField<TUint>* enableWpaPskField = static_cast<CMDBField<TUint>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanEnableWpaPsk ) );
    enableWpaPskField->SetL( iWPAMode );
    
    // Set security mode
    TUint32 secMode;
    if ( iSecurityMode == ESecurityMode8021x )
        {
        secMode = E8021X;
        }
    else if ( iWpa2Only )
        {
        secMode = EWpa2;
        }
    else
        {
        secMode = EWpa;
        }
    CMDBField<TUint>* secModeField = static_cast<CMDBField<TUint>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanSecMode ) );
    secModeField->SetL( secMode );
    
    // Save EAP list
    CMDBField<TDesC>* wlanEapsField = static_cast<CMDBField<TDesC>*>
                                ( generic->GetFieldByIdL( KCDTIdWlanEaps ) );

    // when using the expanded EAP types, wipe out data in the old column
    iWPAEAPPlugin.Zero();

    wlanEapsField->SetL( iWPAEAPPlugin );

    // Save the expanded EAPs
    CMDBField<TDesC8>* wlanEnabledEapsField = static_cast<CMDBField<TDesC8>*>
                           ( generic->GetFieldByIdL( KCDTIdWlanEnabledEaps ) );
    wlanEnabledEapsField->SetL( iWPAEnabledEAPPlugin? 
                                    (const TDesC8&)*iWPAEnabledEAPPlugin: 
                                    (const TDesC8&)KNullDesC8 );


    CMDBField<TDesC8>* wlanDisabledEapsField = static_cast<CMDBField<TDesC8>*>
                          ( generic->GetFieldByIdL( KCDTIdWlanDisabledEaps ) );
    wlanDisabledEapsField->SetL( iWPADisabledEAPPlugin? 
                                    (const TDesC8&)*iWPADisabledEAPPlugin: 
                                    (const TDesC8&)KNullDesC8 );

    // Save PreShared Key
    CMDBField<TDesC8>* wpaPskField = static_cast<CMDBField<TDesC8>*>
                       ( generic->GetFieldByIdL( KCDTIdWlanWpaPreSharedKey ) );
    wpaPskField->SetL( iWPAPreSharedKey );

    // Save PreShared Key length
    CMDBField<TUint>* keyLengthField = static_cast<CMDBField<TUint>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWpaKeyLength ) );
    keyLengthField->SetL( iWPAPreSharedKey.Length() );
    
    TInt error( KErrNone );
    
    // Saving changes
    for ( TInt i( 0 ); i < KRetryCount; i++ )
        {
        
        // If table existed modify it
        if( found )
            {
            TRAP( error, generic->ModifyL( aSession ) );
            }
                   
        // Otherwise store a new record
        else
            {
            generic->SetRecordId( KCDNewRecordRequest );
            TRAP( error, generic->StoreL( aSession ) );
            }
                  
        // If operation failed with KErrLocked, we'll retry.
        if ( KErrLocked == error )
            {
            User::After( KRetryWait );
            }
        
        // Otherwise break the retry loop.
        else 
            {
            break;        
            }
        }
    
    // If the save operation failed, leave now. 
    User::LeaveIfError( error );

    CleanupStack::PopAndDestroy( generic );
            
    if ( iPlugin )
        {
        if ( aTypeOfSaving == ESavingBrandNewAP )
            {
            iPlugin->ChangeIapIDL( aOldIapId, aIapId );
            }
        else if ( aTypeOfSaving == ESavingNewAPAsACopy )
            {
            iPlugin->CopySettingsL( aOldIapId, aIapId );
            }
        }
    }

// End of File
