/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Implementation of EAP Plugin Configuration
*
*/

/*
* %version: 24 %
*/

// INCLUDE FILES
#include "EAPPluginConfiguration.h"
#include "EAPPlugInConfigurationDlg.h"
#include "EAPPluginConfigurationModel.h"
#include <bautils.h>
#include <EapType.h>
#include "EAPPluginList.h"

#include <ecom/ecom.h>
#include <data_caging_path_literals.hrh>
#include <eappluginconfigres.rsg>

// CONSTANTS
_LIT( KDriveZ, "z:" );                               // ROM folder
_LIT( KResourceFileName, "EAPPluginConfigRes.rsc" );   // RSC file name.
_LIT( KSpace, " " );
_LIT( KPlusSign, "+" );
_LIT( KMinusSign, "-" );
_LIT( KComma, "," );


// Length of the UID
static const TInt KLengthOfImplUid = 3;

// Length of expanded EAP type (RFC 3748)
static const TInt KLengthOfExpEapType = 8; 



// ============================ MEMBER FUNCTIONS ===============================

// -----------------------------------------------------------------------------
// CEAPPluginConfiguration::CEAPPluginConfiguration
// -----------------------------------------------------------------------------
//
CEAPPluginConfiguration::CEAPPluginConfiguration()
: iIapId( 0 )
    {
    }


// -----------------------------------------------------------------------------
// CEAPPluginConfiguration::NewL
// -----------------------------------------------------------------------------
//
CEAPPluginConfiguration* CEAPPluginConfiguration::NewL() 
    {
    CEAPPluginConfiguration* self = NewLC();
    CleanupStack::Pop( self );
    return self;
    }

    
// -----------------------------------------------------------------------------
// CEAPPluginConfiguration::NewLC
// -----------------------------------------------------------------------------
//
CEAPPluginConfiguration* CEAPPluginConfiguration::NewLC()
    {
    CEAPPluginConfiguration* self = new( ELeave )CEAPPluginConfiguration();
    CleanupStack::PushL(self);
    self->ConstructL();
    return self;
    }


// -----------------------------------------------------------------------------
// CEAPPluginConfiguration::ConstructL
// -----------------------------------------------------------------------------
//
void CEAPPluginConfiguration::ConstructL()
    {
    }


// -----------------------------------------------------------------------------
// CEAPPluginConfiguration::~CEAPPluginConfiguration
// -----------------------------------------------------------------------------
//
CEAPPluginConfiguration::~CEAPPluginConfiguration()
    {    
    iEapArray.ResetAndDestroy();
    CCoeEnv::Static()->DeleteResourceFile( iResOffset );
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::EAPPluginConfigurationL
// ---------------------------------------------------------
//
TInt CEAPPluginConfiguration::EAPPluginConfigurationL( TDes& aWPAEAPPlugin,
                                                 const TUint32 aIapId, 
                                                 const TDes& aConnectionName )
    {
  	// Adding the resource file to the CoeEnv.
    if( !iResOffset )
        {  		
        TFileName fileName;

        fileName.Append( KDriveZ );
        fileName.Append( KDC_RESOURCE_FILES_DIR );
        fileName.Append( KResourceFileName );
	    
        BaflUtils::NearestLanguageFile( CCoeEnv::Static()->FsSession(), 
                                        fileName );
	    
	    TRAP_IGNORE( iResOffset = 
                            CCoeEnv::Static()->AddResourceFileL( fileName ); );
  	    }       

    TInt buttonId;
    
    REAPPluginList plugins;            ///< Plug-in infos.
    
    LoadPluginInfoL( aWPAEAPPlugin, plugins );
    CEAPPluginConfigurationModel* model = new( ELeave ) 
                                    CEAPPluginConfigurationModel( plugins );
    CleanupStack::PushL( model );

    CEAPPluginConfigurationDlg* pluginDlg = new( ELeave ) 
                        CEAPPluginConfigurationDlg( buttonId, *model, aIapId );

    pluginDlg->ConstructAndRunLD( plugins, aConnectionName );

    SavePluginInfoL( aWPAEAPPlugin, plugins );
    
    CleanupStack::PopAndDestroy( model );
    plugins.Close();
    
    iIapId = aIapId;

    return buttonId;
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::EAPPluginConfigurationL
// ---------------------------------------------------------
//
TInt CEAPPluginConfiguration::EAPPluginConfigurationL( 
                                                TDes8& aWPAEnabledEAPPlugin,
                                                TDes8& aWPADisabledEAPPlugin,
                                                const TUint32 aIapId, 
                                                const TDes& aConnectionName )
    {
  	// Adding the resource file to the CoeEnv.
    if( !iResOffset )
        {  		
        TFileName fileName;

        fileName.Append( KDriveZ );
        fileName.Append( KDC_RESOURCE_FILES_DIR );
        fileName.Append( KResourceFileName );
	    
        BaflUtils::NearestLanguageFile( CCoeEnv::Static()->FsSession(), 
                                        fileName );
	    
	    TRAP_IGNORE( iResOffset = 
                            CCoeEnv::Static()->AddResourceFileL( fileName ); );
  	    }       


    TInt buttonId;
    
    REAPPluginList plugins;            ///< Plug-in infos.
    
    LoadPluginInfoL( aWPAEnabledEAPPlugin, aWPADisabledEAPPlugin, plugins );
    CEAPPluginConfigurationModel* model = new( ELeave ) 
                                    CEAPPluginConfigurationModel( plugins );
    CleanupStack::PushL( model );

    CEAPPluginConfigurationDlg* pluginDlg = new( ELeave ) 
                        CEAPPluginConfigurationDlg( buttonId, *model, aIapId );

    pluginDlg->ConstructAndRunLD( plugins, aConnectionName );

    SavePluginInfoL( aWPAEnabledEAPPlugin, aWPADisabledEAPPlugin, plugins );
    
    CleanupStack::PopAndDestroy( model );
    plugins.Close();
    
    iIapId = aIapId;

    return buttonId;
    }
    

// ---------------------------------------------------------
// CEAPPluginConfiguration::LoadPluginInfoL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::LoadPluginInfoL( TDes& aWPAEAPPlugin, 
                                               REAPPluginList& aPlugins )
    {
    TInt posComma = aWPAEAPPlugin.Locate( ',' );
    while ( posComma != KErrNotFound )                // Extract the parameters
        {
        aWPAEAPPlugin.Replace( posComma, 1, KSpace );
        posComma = aWPAEAPPlugin.Locate( ',' );
        }

    TLex lex( aWPAEAPPlugin );

    CArrayFixFlat<TPtrC>* params;       // array of parameters
    params = new( ELeave ) CArrayFixFlat<TPtrC>( sizeof( TPtrC ) );
    CleanupStack::PushL( params );

    while ( !lex.Eos() )                // Extract the parameters
        {
        params->AppendL( lex.NextToken() );
        }

    aPlugins.Reset();   // Reset this first: dependent on iEapArray.
    iEapArray.ResetAndDestroy();
    REComSession::ListImplementationsL( KEapTypeInterfaceUid, iEapArray );

    // EAP plugin interface dialog should show only the EAP types that allowed
    // outside PEAP.
    
    for( TInt count = 0; count < iEapArray.Count(); count++ )
        {
        // Filter out the EAP types which are NOT allowed outside PEAP.
        if( CEapType::IsDisallowedOutsidePEAP( *iEapArray[count] ) )
            {
            // Delete the EAP type, which isn't allowed outside PEAP, 
            // from the array.
            delete iEapArray[count];
            iEapArray.Remove( count );
            
            // One item removed from the array. So reduce the item count.
            count--;
            }
        }

    TInt numParams = params->Count();
    TBool foundDefaultEAPTypes = EFalse;
    
    // Rearrange the array so that EAP-SIM and EAP-AKA are on top, in that order.
    
    // The rearrange is needed only for the first time creation.
    if ( numParams == 0 )
        {
        TInt topPos = 0; // position in the beginning of arrary.
        TInt error( KErrNone );

        // First move EAP-AKA to top, if it is present in the array.
        error = MoveEAPType( EAPSettings::EEapAka, topPos );

        if ( error != KErrNotFound )
            {
            // Found EAP-AKA in the array. 
            // Doesn't matter if the move was a success or not.
            foundDefaultEAPTypes = ETrue;
            }

        // Now move EAP-SIM to top. 
        // EAP-SIM will be always the top most if it is present in the array.
        // Otherwise EAP-AKA stays in the top, if it is present.
        // The order doesn't matter if these two are not present.
        MoveEAPType( EAPSettings::EEapSim, topPos );

        if( error != KErrNotFound)
            {
            // Found EAP-SIM in the array. 
            // Doesn't matter if the move was a success.
            foundDefaultEAPTypes = ETrue;
            }   
        }

    TInt i;
    TInt j;
    TInt numInfoStore = iEapArray.Count();
    TInt eapUid;
    
    // just to make sure we are not given a non-empty but fully disabled list
    TBool gotEnabled = EFalse;

    CArrayFix<TInt>* usedImplInfo = new( ELeave ) CArrayFixFlat<TInt>( 4 );
    CleanupStack::PushL( usedImplInfo );
    usedImplInfo->AppendL( 0, numInfoStore );

    for ( j = 0; j < numParams; j++ )
        {
        TLex lexUid( params->At( j ) );
        if ( lexUid.Val( eapUid ) == KErrNone )
            {
            for ( i = 0; i < numInfoStore; i++ )
                {
                TLex8 lexDataType( iEapArray[i]->DataType() );
                TInt implUID;

                if ( lexDataType.Val( implUID ) == KErrNone )
                    {
                    if ( implUID == Abs( eapUid ) )
                        {
                        usedImplInfo->InsertL( i, 1 );
                        if ( i+1 < usedImplInfo->Count() )
                            {
                            usedImplInfo->Delete( i+1 );
                            }

                        TEAPPluginInfo plugin;
                        plugin.iInfo = iEapArray[i];

                        plugin.iEnabled = ( eapUid > 0 || 
                                ( eapUid == 0 && 
                                  params->At( j ).Left( 1 ) == KPlusSign ) );
                        User::LeaveIfError( aPlugins.Append( plugin ) );
                        gotEnabled = gotEnabled || plugin.iEnabled;
                        i = numInfoStore;  // to exit from cycle
                        }
                    }
                }   
            }
        }

    for ( i = 0; i < numInfoStore; i++ )
        {
        if ( !usedImplInfo->At( i ) )
            {
            TEAPPluginInfo plugin;
            plugin.iInfo = iEapArray[i];
            
            // Default is enabled. 
            // There should not be a case of all EAP types disabled.
            TBool defaultEnableValue( ETrue ); 
            
            if ( numParams > 0 && gotEnabled)
                {
                // If there some EAP types which are already enabled/disabled,
                // we make the new EAP types disabled.
                defaultEnableValue = EFalse;
                }
            else
                {
                // Nothing in the string or all disabled.
                // Should be the first time execution (creating new IAP).
                // Only EAP-SIM and EAP-AKA are enabled in this case.
                TLex8 lexDataType( iEapArray[i]->DataType() );
                TInt implDataType;
                
                if ( lexDataType.Val( implDataType ) == KErrNone )
                    {
                    if( foundDefaultEAPTypes )
                        {
                        defaultEnableValue = 
                                    ( implDataType == EAPSettings::EEapSim ||
                                      implDataType == EAPSettings::EEapAka );
                        }
                    else
                        {
                        // No default EAPs (No EAP-SIM and EAP-AKA). 
                        // So all EAP types are enabled by default.
                        defaultEnableValue = ETrue;
                        }
                    }
                }

            plugin.iEnabled = defaultEnableValue;
            User::LeaveIfError( aPlugins.Append( plugin ) );
            }
        }

    CleanupStack::PopAndDestroy( 2, params );  // usedImplInfo, params
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::LoadPluginInfoL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::LoadPluginInfoL( TDes8& aWPAEnabledEAPPlugin, 
                                               TDes8& aWPADisabledEAPPlugin, 
                                               REAPPluginList& aPlugins )
    {
    // size of aWPAEnabledEAPPlugin and aWPADisabledEAPPlugin must be 
    // divisible by KLengthOfExpEapType
    __ASSERT_DEBUG( ( aWPAEnabledEAPPlugin.Size() % KLengthOfExpEapType == 0 ), 
                    User::Panic( _L( "aWPAEnabledEAPPlugin is corrupted!" ), KErrCorrupt ) );
                     
    __ASSERT_DEBUG( ( aWPADisabledEAPPlugin.Size() % KLengthOfExpEapType == 0 ), 
                    User::Panic( _L( "aWPADisabledEAPPlugin is corrupted!" ), KErrCorrupt ) );
    

    aPlugins.Reset();   // Reset this first: dependent on iEapArray.
    iEapArray.ResetAndDestroy();
    REComSession::ListImplementationsL( KEapTypeInterfaceUid, iEapArray );

    // EAP plugin interface dialog should show only the EAP types that allowed
    // outside PEAP.
    
    for( TInt count = 0; count < iEapArray.Count(); count++ )
        {
        // Filter out the EAP types which are NOT allowed outside PEAP.
        if( CEapType::IsDisallowedOutsidePEAP( *iEapArray[count] ) )
            {
            // Delete the EAP type, which isn't allowed outside PEAP, 
            // from the array.
            delete iEapArray[count];
            iEapArray.Remove( count );
            
            // One item removed from the array. So reduce the item count.
            count--;
            }
        }

    TInt numEnabled = aWPAEnabledEAPPlugin.Size() / KLengthOfExpEapType;
    TInt numDisabled = aWPADisabledEAPPlugin.Size() / KLengthOfExpEapType;
    TBool foundDefaultEAPTypes = EFalse;
    
    // Rearrange the array so that EAP-SIM and EAP-AKA are on top, in that order.
    
    // The rearrange is needed only for the first time creation.
    if ( !( numEnabled || numDisabled ) )
        {
        TInt topPos = 0; // position in the beginning of array.
        TInt error( KErrNone );

        // First move EAP-AKA to top, if it is present in the array.
        _LIT8( KExpEapTypeFormat, "\xFE\0\0\0%c%c%c%c" );
        TBuf8<KLengthOfExpEapType> tmpEap;
        
        // BigEndian::Put32( const_cast<TUint8*>( tmpEap.Ptr() ) + 4, 
        //                  EAPSettings::EEapAka );
        tmpEap.Format( KExpEapTypeFormat, ( EAPSettings::EEapAka >> 24 ) & 0xff, 
                                          ( EAPSettings::EEapAka >> 16 ) & 0xff,
                                          ( EAPSettings::EEapAka >> 8 ) & 0xff,
                                          EAPSettings::EEapAka & 0xff );
                                          
        error = MoveEAPType( tmpEap, topPos );

        if ( error != KErrNotFound )
            {
            // Found EAP-AKA in the array. 
            // Doesn't matter if the move was a success or not.
            foundDefaultEAPTypes = ETrue;
            }

        // Now move EAP-SIM to top. 
        // EAP-SIM will be always the top most if it is present in the array.
        // Otherwise EAP-AKA stays in the top, if it is present.
        // The order doesn't matter if these two are not present.
        // BigEndian::Put32( const_cast<TUint8*>( tmpEap.Ptr() ) + 4, 
        //                  EAPSettings::EEapSim );
        tmpEap.Format( KExpEapTypeFormat, ( EAPSettings::EEapSim >> 24 ) & 0xff, 
                                          ( EAPSettings::EEapSim >> 16 ) & 0xff,
                                          ( EAPSettings::EEapSim >> 8 ) & 0xff,
                                          EAPSettings::EEapSim & 0xff );
                                          
        error = MoveEAPType( tmpEap, topPos );

        if( error != KErrNotFound)
            {
            // Found EAP-SIM in the array. 
            // Doesn't matter if the move was a success.
            foundDefaultEAPTypes = ETrue;
            }   
        }

    TInt i;
    TInt j;
    TInt numInfoStore = iEapArray.Count();

    CArrayFix<TInt>* usedImplInfo = new( ELeave ) CArrayFixFlat<TInt>( 4 );
    CleanupStack::PushL( usedImplInfo );
  
    usedImplInfo->AppendL( 0, numInfoStore );

    // deal with the enabled first
    for ( j = 0; j < numEnabled; j++ )
        {
    	TPtrC8 param( aWPAEnabledEAPPlugin.Ptr() + KLengthOfExpEapType * j, 
    	              KLengthOfExpEapType );
    	
        for ( i = 0; i < numInfoStore; i++ )
            {
            if ( !param.Compare( iEapArray[i]->DataType() ) )
                {
                usedImplInfo->InsertL( i, 1 );
                if ( i+1 < usedImplInfo->Count() )
                    {
                    usedImplInfo->Delete( i+1 );
                    }

                TEAPPluginInfo plugin;
                plugin.iInfo = iEapArray[i];
                plugin.iEnabled = ETrue;
                
                User::LeaveIfError( aPlugins.Append( plugin ) );
                i = numInfoStore;  // to exit from cycle
                }
            }   
        }


    // now come the disabled
    for ( j = 0; j < numDisabled; j++ )
        {
    	TPtrC8 param( aWPADisabledEAPPlugin.Ptr() + KLengthOfExpEapType * j, 
    	              KLengthOfExpEapType );
    	
        for ( i = 0; i < numInfoStore; i++ )
            {
            if ( !param.Compare( iEapArray[i]->DataType() ) )
                {
                usedImplInfo->InsertL( i, 1 );
                if ( i+1 < usedImplInfo->Count() )
                    {
                    usedImplInfo->Delete( i+1 );
                    }

                TEAPPluginInfo plugin;
                plugin.iInfo = iEapArray[i];
                plugin.iEnabled = EFalse;
                
                User::LeaveIfError( aPlugins.Append( plugin ) );
                i = numInfoStore;  // to exit from cycle
                }
            }   
        }
        

    for ( i = 0; i < numInfoStore; i++ )
        {
        if ( !usedImplInfo->At( i ) )
            {
            TEAPPluginInfo plugin;
            plugin.iInfo = iEapArray[i];
            
            // Default is enabled. 
            // There should not be a case of all EAP types disabled.
            TBool defaultEnableValue( ETrue ); 
            
            if ( numEnabled > 0 )
                {
                // If there some EAP types which are already enabled/disabled,
                // we make the new EAP types disabled.
                defaultEnableValue = EFalse;
                }
            else
                {
                // No EAP types enabled. 
                // Should be the first time execution (creating new IAP).
                // Only EAP-SIM and EAP-AKA are enabled in this case.
                
                // [FE] [00 00 00] [TEapType_bigendian]
                const TDesC8& cue = iEapArray[i]->DataType();
                
                TPtrC8 eapType( cue.Ptr() + 4, 4 );
                TUint32 implDataType = ( eapType[0] << 24 ) |
                                       ( eapType[1] << 16 ) |
                                       ( eapType[2] << 8 ) |
                                       eapType[3];

                if( foundDefaultEAPTypes )
                    {
                    _LIT8( KExpEapFirstQuad, "\xFE\0\0\0" );
                    TPtrC8 firstQuad( cue.Ptr(), 4 );
                    
                    defaultEnableValue = 
                            ( !firstQuad.Compare ( KExpEapFirstQuad ) &&
                                ( implDataType == EAPSettings::EEapSim ||
                                  implDataType == EAPSettings::EEapAka ) );
                    }
                else
                    {
                    // No default EAPs (No EAP-SIM and EAP-AKA). 
                    // So all EAP types are enabled by default.
                    defaultEnableValue = ETrue;
                    }
                }

            plugin.iEnabled = defaultEnableValue;
            User::LeaveIfError( aPlugins.Append( plugin ) );
            }
        }
    CleanupStack::PopAndDestroy( usedImplInfo );
    
    }
    

// ---------------------------------------------------------
// CEAPPluginConfiguration::SavePluginInfoL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::SavePluginInfoL( TDes& aWPAEAPPlugin, 
                                               REAPPluginList& aPlugins )
    {
    aWPAEAPPlugin.Zero();
    for ( TInt index = 0; index < aPlugins.Count(); index++ )
        {
        TBuf8<KLengthOfImplUid> cue = aPlugins[index].iInfo->DataType(); 

        TLex8 lexDataType( cue );
        TInt implUID;
        if ( lexDataType.Val( implUID ) == KErrNone )
            {
            if ( aPlugins[index].iEnabled )
                {
                aWPAEAPPlugin.Append( KPlusSign );
                }
            else
                {
                aWPAEAPPlugin.Append( KMinusSign );
                }

            aWPAEAPPlugin.AppendNumFixedWidth( implUID, EDecimal, 
                                               KLengthOfImplUid );

            if ( index != aPlugins.Count()-1 )
                {
                aWPAEAPPlugin.Append( KComma );
                }
            }
        }
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::SavePluginInfoL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::SavePluginInfoL( TDes8& aWPAEnabledEAPPlugin, 
                                               TDes8& aWPADisabledEAPPlugin, 
                                               REAPPluginList& aPlugins )
    {
    aWPAEnabledEAPPlugin.Zero();
    aWPADisabledEAPPlugin.Zero();
    
    for ( TInt index = 0; index < aPlugins.Count(); index++ )
        {
        if ( aPlugins[index].iEnabled )
            {
            aWPAEnabledEAPPlugin.Append( aPlugins[index].iInfo->DataType() );
            }
        else
            {
            aWPADisabledEAPPlugin.Append( aPlugins[index].iInfo->DataType() );
            }
        } 
    
    }
    

// ---------------------------------------------------------
// CEAPPluginConfiguration::ShowEAPTypeInfo
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::ShowEAPTypeInfo()
    {    
    
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::DeleteSettingsL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::DeleteSettingsL( const TUint32 aIapID )
    {    
    iEapArray.ResetAndDestroy();
    REComSession::ListImplementationsL( KEapTypeInterfaceUid, iEapArray );
        
    for ( TInt i = 0; i < iEapArray.Count(); i++ )
        {
        if ( !CEapType::IsDisallowedOutsidePEAP( *iEapArray[i] ) )
            {
            CEapType* eapType = CEapType::NewL( iEapArray[i]->DataType(), 
                                                ELan, 
                                                aIapID );
            CleanupStack::PushL( eapType );
            
            eapType->DeleteConfigurationL();
            CleanupStack::PopAndDestroy( eapType );
            }
        }    
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::ChangeIapIDL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::ChangeIapIDL( const TUint32 aOldIapID,
                                            const TUint32 aNewIapID )
    {
    iEapArray.ResetAndDestroy();
    REComSession::ListImplementationsL( KEapTypeInterfaceUid, iEapArray );
        
    for ( TInt i = 0; i < iEapArray.Count(); i++ )
        {
        if ( !CEapType::IsDisallowedOutsidePEAP( *iEapArray[i] ) )
            {
            CEapType* eapType = CEapType::NewL( iEapArray[i]->DataType(), 
                                                ELan, 
                                                aOldIapID );
            CleanupStack::PushL( eapType );
            
            eapType->SetIndexL( ELan, aNewIapID );
            CleanupStack::PopAndDestroy( eapType );
        }
    }    
}

// ---------------------------------------------------------
// CEAPPluginConfiguration::CopySettingsL
// ---------------------------------------------------------
//
void CEAPPluginConfiguration::CopySettingsL( const TUint32 aSourceIapID,
	                                         const TUint32 aDestinationIapID )
    {
	iEapArray.ResetAndDestroy();
	REComSession::ListImplementationsL( KEapTypeInterfaceUid, iEapArray );
		
	for ( TInt i = 0; i < iEapArray.Count(); i++ )
	    {
		if ( !CEapType::IsDisallowedOutsidePEAP( *iEapArray[i] ) )
		    {
			CEapType* eapType = CEapType::NewL( iEapArray[i]->DataType(), 
			                                    ELan, 
			                                    aSourceIapID );
			CleanupStack::PushL( eapType );
			
			eapType->CopySettingsL( ELan, aDestinationIapID );
			CleanupStack::PopAndDestroy( eapType );
    		}
	    }	
    }
        

// ---------------------------------------------------------
// CEAPPluginConfiguration::MoveEAPType
// ---------------------------------------------------------
//
TInt CEAPPluginConfiguration::MoveEAPType( EAPSettings::TEapType aEapType, 
                                           TInt aPos )
    {
    TInt error( KErrNotFound );

    // Parse the array to find out the desired EAP type.
    for( TInt count = 0; count < iEapArray.Count(); count++ )
        {
        TLex8 lexDataType( iEapArray[count]->DataType() );
        TInt implDataType;
        
        if ( lexDataType.Val( implDataType ) == KErrNone )
            {
            if ( implDataType == aEapType )
                {
                // Move this to the required destination.
                error = iEapArray.Insert( iEapArray[count], aPos );

                if( KErrNone == error )
                    {
                    // Delete the old entry. It should be one count up now.
                    iEapArray.Remove( count+1 );          			
                    }
                else
                    {
                    // Some problem. Couldn't move.
                    error = KErrUnknown;
                    }

                // No need to parse further in the array. 
                // We found the needed EAP type.
                break; 
                }
            }
        else
            {
            error = KErrGeneral;
            }
        }

    return error;
    }


// ---------------------------------------------------------
// CEAPPluginConfiguration::MoveEAPType
// ---------------------------------------------------------
//
TInt CEAPPluginConfiguration::MoveEAPType( const TDesC8& aEapType, TInt aPos )
    {
    TInt error( KErrNotFound );

    // Parse the array to find out the desired EAP type.
    for( TInt count = 0; count < iEapArray.Count(); count++ )
        {
        if ( !iEapArray[count]->DataType().Compare( aEapType ) )
            {
            // Move this to the required destination.
            error = iEapArray.Insert( iEapArray[count], aPos );

            if( KErrNone == error )
                {
                // Delete the old entry. It should be one count up now.
                iEapArray.Remove( count+1 );          			
                }
            else
                {
                // Some problem. Couldn't move.
                error = KErrUnknown;
                }

            // No need to parse further in the array. 
            // We found the needed EAP type.
            break; 
            }
        }

    return error;
    }

// End of file.
