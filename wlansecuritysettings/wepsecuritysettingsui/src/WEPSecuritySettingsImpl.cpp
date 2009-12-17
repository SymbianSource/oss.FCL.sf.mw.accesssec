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
* Description: Implementation of class CWEPSecuritySettingsImpl.     
*
*/


// INCLUDE FILES

#include "WEPSecuritySettingsImpl.h"
#include "WEPSecuritySettingsUiPanic.h"

#include <WEPSecuritySettingsUI.h>
#include <commdb.h>
#include <FeatMgr.h>
#include <WlanCdbCols.h>

#include <commsdattypesv1_1.h>
#include <cmmanagertablefields.h>
#include <wlancontainer.h>

// CONSTANT DECLARATIONS

// Index of first key
LOCAL_D const TInt KFirstKey = 0;

// Index of second key
LOCAL_D const TInt KSecondKey = 1;

// Index of third key
LOCAL_D const TInt KThirdKey = 2;

// Index of fourth key
LOCAL_D const TInt KFourthKey = 3;

// Ratio of ascii and hex key sizes
LOCAL_D const TInt KAsciiHexRatio = 2;


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::NewL
// ---------------------------------------------------------
//
CWEPSecuritySettingsImpl* CWEPSecuritySettingsImpl::NewL()
    {
    CWEPSecuritySettingsImpl* settings = 
                                    new ( ELeave ) CWEPSecuritySettingsImpl();
    CleanupStack::PushL( settings );
    settings->ConstructL();
    CleanupStack::Pop( settings ); 
    return settings;    
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::CWEPSecuritySettingsImpl
// ---------------------------------------------------------
//
CWEPSecuritySettingsImpl::CWEPSecuritySettingsImpl()
: iIsWEP256Enabled( ETrue )
    {
    iKeyInUse = CWEPSecuritySettings::EKeyNumber1;
    iAuthentication = CWEPSecuritySettings::EAuthOpen;
    for ( TUint i = 0; i < KMaxNumberofKeys; i++)
        {
        iKeyLength[i] = CWEPSecuritySettings::E40Bits;
        iKeyFormat[i] = CWEPSecuritySettings::EAscii;
        iKeyData[i].Zero();
        }
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::ConstructL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsImpl::ConstructL()
    {
    // WEP256 is deprecated.
    iIsWEP256Enabled = EFalse;
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::~CWEPSecuritySettingsImpl
// ---------------------------------------------------------
//
CWEPSecuritySettingsImpl::~CWEPSecuritySettingsImpl()
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::LoadL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsImpl::LoadL( TUint32 aIapId, 
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
        // Get index of key in use
        TRAPD( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_WEP_INDEX ),
                                    ( TUint32& ) iKeyInUse ) );

        // Get index of key in use
        TRAP( err, wLanServiceTable->ReadUintL( 
                                        TPtrC( NU_WLAN_AUTHENTICATION_MODE ),
                                        ( TUint32& ) iAuthentication ) );

        // Get first WEP key
        wLanServiceTable->ReadTextL( TPtrC( NU_WLAN_WEP_KEY1 ), 
                                     iKeyData[KFirstKey] );
        SetLenKeyDataFromText( KFirstKey );

        // Get second WEP key
        wLanServiceTable->ReadTextL( TPtrC( NU_WLAN_WEP_KEY2 ), 
                                     iKeyData[KSecondKey] );
        SetLenKeyDataFromText( KSecondKey );

        // Get third WEP key
        wLanServiceTable->ReadTextL( TPtrC( NU_WLAN_WEP_KEY3 ), 
                                     iKeyData[KThirdKey] );
        SetLenKeyDataFromText( KThirdKey );

        // Get fourth WEP key
        wLanServiceTable->ReadTextL( TPtrC( NU_WLAN_WEP_KEY4 ), 
                                     iKeyData[KFourthKey] );
        SetLenKeyDataFromText( KFourthKey );


        // Get the format of the keys
        TRAP( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_WEP_KEY1_FORMAT ),
                                    ( TUint32& ) iKeyFormat[KFirstKey] ) );

        TRAP( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_WEP_KEY2_FORMAT ),
                                    ( TUint32& ) iKeyFormat[KSecondKey] ) );

        TRAP( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_WEP_KEY3_FORMAT ),
                                    ( TUint32& ) iKeyFormat[KThirdKey] ) );

        TRAP( err, wLanServiceTable->ReadUintL( TPtrC( WLAN_WEP_KEY4_FORMAT ),
                                    ( TUint32& ) iKeyFormat[KFourthKey] ) );
        }
    else
        {
        // silently ignore KErrNotFound. It is caused by incorrect DB,
        // we are 'repairing it' this way.
        if ( errorCode != KErrNotFound )
            {
            User::Leave( errorCode );
            }
        }

    CleanupStack::PopAndDestroy( wLanServiceTable );  // wLanServiceTable
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SaveL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsImpl::SaveL( TUint32 aIapId, 
                                      CCommsDatabase& aCommsDb ) const
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

    // Save index of key in use
    wLanServiceTable->WriteUintL( TPtrC( WLAN_WEP_INDEX ), 
                                 ( TUint32& ) iKeyInUse );

    // Save index of key in use
    wLanServiceTable->WriteUintL( TPtrC( NU_WLAN_AUTHENTICATION_MODE ), 
                                 ( TUint32& ) iAuthentication );

    // Save first WEP key
    wLanServiceTable->WriteTextL( TPtrC( NU_WLAN_WEP_KEY1 ), 
                                  iKeyData[KFirstKey] );

    // Save second WEP key
    wLanServiceTable->WriteTextL( TPtrC( NU_WLAN_WEP_KEY2 ), 
                                  iKeyData[KSecondKey] );

    // Save third WEP key
    wLanServiceTable->WriteTextL( TPtrC( NU_WLAN_WEP_KEY3 ), 
                                  iKeyData[KThirdKey] );

    // Save fourth WEP key
    wLanServiceTable->WriteTextL( TPtrC( NU_WLAN_WEP_KEY4 ), 
                                  iKeyData[KFourthKey] );

    // Save the format of the keys
    wLanServiceTable->WriteUintL( TPtrC( WLAN_WEP_KEY1_FORMAT ), 
                                 ( TUint32& ) iKeyFormat[KFirstKey] );

    wLanServiceTable->WriteUintL( TPtrC( WLAN_WEP_KEY2_FORMAT ), 
                                 ( TUint32& ) iKeyFormat[KSecondKey] );

    wLanServiceTable->WriteUintL( TPtrC( WLAN_WEP_KEY3_FORMAT ), 
                                 ( TUint32& ) iKeyFormat[KThirdKey] );

    wLanServiceTable->WriteUintL( TPtrC( WLAN_WEP_KEY4_FORMAT ), 
                                 ( TUint32& ) iKeyFormat[KFourthKey] );

    wLanServiceTable->PutRecordChanges();

    CleanupStack::PopAndDestroy( wLanServiceTable );  // wLanServiceTable
    }
    

// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetLenKeyDataFromText
// ---------------------------------------------------------
//
void CWEPSecuritySettingsImpl::SetLenKeyDataFromText( const TInt aIndex )
    {
    const TUint keyDataLength = iKeyData[aIndex].Length();

    if ( keyDataLength == KKeyDataLength104Bits )
        {
        iKeyLength[aIndex] = CWEPSecuritySettings::E104Bits;
        }
    else if ( keyDataLength == KKeyDataLength232Bits && iIsWEP256Enabled )
        {
        iKeyLength[aIndex] = CWEPSecuritySettings::E232Bits;
        }
    else            // if ( aKeyDataLength == KKeyDataLength40Bits ) or any
        {           //  other case, by default
        iKeyLength[aIndex] = CWEPSecuritySettings::E40Bits;
        }
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::IsValid
// ---------------------------------------------------------
//
TBool CWEPSecuritySettingsImpl::IsValid()
    {
    return ( KeyData( KeyInUse() )->Length() == 
                        ExpectedLengthOfKeyData( KeyLength( KeyInUse() ) ) );
    }


//----------------------------------------------------------
// CWEPSecuritySettingsImpl::ExpectedLengthOfKeyData
//----------------------------------------------------------
//
TInt CWEPSecuritySettingsImpl::ExpectedLengthOfKeyData( 
                               CWEPSecuritySettings::TWEPKeyLength aKeyLength )
    {
    TInt retVal;

    switch ( aKeyLength )
        {
        case CWEPSecuritySettings::E40Bits:
            {
            retVal = KKeyDataLength40Bits;
            break;
            }

        case CWEPSecuritySettings::E104Bits:
            {
            retVal = KKeyDataLength104Bits;
            break;
            }

        case CWEPSecuritySettings::E232Bits:
            {
            retVal = WEP256Enabled() ? KKeyDataLength232Bits : 0;
            break;
            }

        default:
            {
            retVal = 0;
            break;
            }
        }

    return retVal;
    }
 


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetKeyDataL
// ---------------------------------------------------------
//
TInt CWEPSecuritySettingsImpl::SetKeyDataL( const TInt aElement, 
                                            const TDesC& aKeyData,
                                            const TBool aHex )
    {
    CWEPSecuritySettings::TWEPKeyFormat keyFormat = aHex ? 
                                    CWEPSecuritySettings::EHexadecimal : 
                                    CWEPSecuritySettings::EAscii;
    SetKeyFormat( aElement, keyFormat );

    TInt dataLength = aKeyData.Length();
    if ( dataLength == KKeyDataLength40Bits ||
         dataLength == KKeyDataLength40Bits / KAsciiHexRatio )
        {
        SetKeyLength( aElement, CWEPSecuritySettings::E40Bits );
        }
    else if ( dataLength == KKeyDataLength104Bits ||
         dataLength == KKeyDataLength104Bits / KAsciiHexRatio )
        {
        SetKeyLength( aElement, CWEPSecuritySettings::E104Bits );
        }
    else if ( dataLength == KKeyDataLength232Bits ||
         dataLength == KKeyDataLength232Bits / KAsciiHexRatio )
        {
        SetKeyLength( aElement, CWEPSecuritySettings::E232Bits );
        }
    else
        {
        return KErrInvalidLength;
        }

    TInt expectedLength = ExpectedLengthOfKeyData( KeyLength( aElement ) );

    if ( keyFormat == CWEPSecuritySettings::EAscii )
        {
        expectedLength /= KAsciiHexRatio; //Ascii key is half the length of Hex
        }

    HBufC8* buf8 = HBufC8::NewL( dataLength );
    CleanupStack::PushL( buf8 );
    buf8->Des().Copy( aKeyData ); 

    TInt errData = VerifyKeyData( *buf8, expectedLength, 
                                  KeyFormat( aElement ) );
    if ( errData == KErrNone )
        {
        if ( aHex )
            {
            SetKeyData( aElement, buf8->Des() );
            }
        else
            {
            HBufC8* buf8Conv = HBufC8::NewL( dataLength * KAsciiHexRatio );
                                // Ascii key is half the length of Hex
            ConvertAsciiToHex( buf8->Des(), buf8Conv );
            SetKeyData( aElement, buf8Conv->Des() );
            delete buf8Conv;
            }
        }

    CleanupStack::PopAndDestroy( buf8 ); // buf8

    return errData;
    }


//----------------------------------------------------------
// CWEPSecuritySettingsImpl::VerifyKeyData
//----------------------------------------------------------
//
TInt CWEPSecuritySettingsImpl::VerifyKeyData( const TDesC8& aTextToTest,
                                             TInt aLengthOfKeyData,
                            CWEPSecuritySettings::TWEPKeyFormat aWEPKeyFormat )
    {
    TInt err = KErrNone;
    TInt lengthOfText = aTextToTest.Length();

    if ( aTextToTest.Length() != aLengthOfKeyData )
        {
        err = KErrInvalidLength;
        }
    else if ( aWEPKeyFormat == CWEPSecuritySettings::EHexadecimal )
        {
        for ( TInt i = 0; i < lengthOfText; i++ )
            {
            TChar c ( aTextToTest[i] );

            if ( !c.IsHexDigit() ) 
                {
                err = KErrInvalidChar;
                break;
                }
            }
        }

    return err;
    }


//----------------------------------------------------------
// CWEPSecuritySettingsImpl::ConvertAsciiToHex
//----------------------------------------------------------
//
void CWEPSecuritySettingsImpl::ConvertAsciiToHex( const TDesC8& aSource, 
                                                  HBufC8*& aDest )
	{
	_LIT( hex, "0123456789ABCDEF" );
	TInt size = aSource.Size();
	TPtr8 ptr = aDest->Des();
	for ( TInt ii = 0; ii < size; ii++ )
		{
		TText8 ch = aSource[ii];
		ptr.Append( hex()[(ch/16)&0x0f] );
		ptr.Append( hex()[ch&0x0f] );
		}
	}


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::LoadL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsImpl::LoadL( TUint32 aIapId, 
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
                                    (generic->GetFieldByIdL( KCDTIdWlanServiceId));
    
    // prime with service id                
    *sidField = aIapId;

    if( generic->FindL( aSession) )
        {
        // get the values
        CMDBField<TUint>* keyInUseField = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanWepIndex ) );
        ( TUint32& )iKeyInUse = *keyInUseField;
        CMDBField<TUint>* authenticationField = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanAuthMode ) );
        ( TUint32& )iAuthentication = *authenticationField;
        
        CMDBField<TDesC8>* wepKey1Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey1 ) );
        iKeyData[ KFirstKey ] = *wepKey1Field;
        SetLenKeyDataFromText( KFirstKey );
        
        CMDBField<TDesC8>* wepKey2Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey2 ) );
        iKeyData[ KSecondKey ] = *wepKey2Field;
        SetLenKeyDataFromText( KSecondKey );
        
        CMDBField<TDesC8>* wepKey3Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey3 ) );
        iKeyData[ KThirdKey ] = *wepKey3Field;
        SetLenKeyDataFromText( KThirdKey );
        
        CMDBField<TDesC8>* wepKey4Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey4 ) );
        iKeyData[ KFourthKey ] = *wepKey4Field;
        SetLenKeyDataFromText( KFourthKey );
        
        CMDBField<TUint>* formatKey1Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey1 ) );
        ( TUint32& )iKeyFormat[ KFirstKey ] = *formatKey1Field;
        CMDBField<TUint>* formatKey2Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey2 ) );
        ( TUint32& )iKeyFormat[ KSecondKey ] = *formatKey2Field;
        CMDBField<TUint>* formatKey3Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey3 ) );
        ( TUint32& )iKeyFormat[ KThirdKey ] = *formatKey3Field;
        CMDBField<TUint>* formatKey4Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey4 ) );
        ( TUint32& )iKeyFormat[ KFourthKey ] = *formatKey4Field;
        }

    CleanupStack::PopAndDestroy( generic );
    
    }
    

// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SaveL
// ---------------------------------------------------------
//
void CWEPSecuritySettingsImpl::SaveL( TUint32 aIapId, 
                                      CMDBSession& aSession ) const
    {
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
    
    CMDBField<TUint>* keyInUseField = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanWepIndex ) );
    keyInUseField->SetL( iKeyInUse );

    CMDBField<TUint>* authenticationField = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanAuthMode ) );
    authenticationField->SetL( iAuthentication );
    
    CMDBField<TDesC8>* wepKey1Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey1 ) );
    wepKey1Field->SetL( iKeyData[ KFirstKey ] );
    CMDBField<TDesC8>* wepKey2Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey2 ) );
    wepKey2Field->SetL( iKeyData[ KSecondKey ] );
    CMDBField<TDesC8>* wepKey3Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey3 ) );
    wepKey3Field->SetL( iKeyData[ KThirdKey ] );
    CMDBField<TDesC8>* wepKey4Field = static_cast<CMDBField<TDesC8>*>
                        ( generic->GetFieldByIdL( KCDTIdWlanWepKey4 ) );
    wepKey4Field->SetL( iKeyData[ KFourthKey ] );
    
    CMDBField<TUint>* formatKey1Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey1 ) );
    formatKey1Field->SetL( iKeyFormat[ KFirstKey ] );
    CMDBField<TUint>* formatKey2Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey2 ) );
    formatKey2Field->SetL( iKeyFormat[ KSecondKey ] );
    CMDBField<TUint>* formatKey3Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey3 ) );
    formatKey3Field->SetL( iKeyFormat[ KThirdKey ] );
    CMDBField<TUint>* formatKey4Field = static_cast<CMDBField<TUint>*>
                            ( generic->GetFieldByIdL( KCDTIdWlanFormatKey4 ) );
    formatKey4Field->SetL( iKeyFormat[ KFourthKey ] );
    
    // If table existed modify it
    if( found )
        {
        generic->ModifyL( aSession );
        }
    // Otherwise store a new record
    else
        {
        generic->SetRecordId( KCDNewRecordRequest );
        generic->StoreL( aSession );
        }
    CleanupStack::PopAndDestroy( generic );
    }


// End of File
