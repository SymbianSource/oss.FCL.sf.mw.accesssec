/*
* ============================================================================
*  Name     : wapisecuritysettings.cpp 
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Implementation of class CWAPISecuritySettings.   
*      
*  Version: %version:  9 %
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

#include <wapisecuritysettingsui.h>

#include "wapisecuritysettingsimpl.h"
#include "wapisecuritysettingsuiimpl.h"


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettings::NewL
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettings* CWAPISecuritySettings::NewL()
    {
    CWAPISecuritySettings* settings = new ( ELeave ) CWAPISecuritySettings();
    CleanupStack::PushL( settings );
    settings->iImpl = CWAPISecuritySettingsImpl::NewL();
    CleanupStack::Pop( settings ); 
    return settings;    
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::~CWAPISecuritySettings
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettings::~CWAPISecuritySettings()
    {
    delete iImpl;
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::EditL
// ---------------------------------------------------------
//
EXPORT_C TInt CWAPISecuritySettings::EditL( CWAPISecuritySettingsUi& aUi,
                                           const TDesC& aTitle )
    {
    return aUi.iImpl->EditL( *iImpl, aTitle );
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::LoadL( TUint32 aIapRecordId, CMDBSession& aSession )
    {
    iImpl->LoadL( aIapRecordId, aSession );
    }
    

// ---------------------------------------------------------
// CWAPISecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C TBool CWAPISecuritySettings::IsValid( ) const
    {
    return iImpl->IsValid( );
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::SaveL( TUint32 aIapRecordId, CMDBSession& aSession ) const
    {
    iImpl->SaveL( aIapRecordId, aSession );
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::SetPreSharedKey
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::SetPreSharedKeyL( const TWapiKeyFormat aKeyFormat, const TDesC& aPreSharedKey )
    {
    iImpl->SetPreSharedKeyL(aKeyFormat, aPreSharedKey);
    }

// ---------------------------------------------------------
// CWAPISecuritySettings::DeleteAPSpecificDataL
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::DeleteAPSpecificDataL( const TInt aId )
    {
    iImpl->DeleteAPSpecificDataL( aId );
    }

// End of File
