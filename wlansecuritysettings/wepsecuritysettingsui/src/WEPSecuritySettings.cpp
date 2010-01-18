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
* Description: Implementation of class CWEPSecuritySettings.     
*
*/

/*
* %version: tr1cfwln#15 %
*/

// INCLUDE FILES

#include <WEPSecuritySettingsUI.h>

#include "WEPSecuritySettingsImpl.h"
#include "WEPSecuritySettingsUiImpl.h"


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPSecuritySettings::NewL
// ---------------------------------------------------------
//
EXPORT_C CWEPSecuritySettings* CWEPSecuritySettings::NewL()
    {
    CWEPSecuritySettings* settings = new ( ELeave ) CWEPSecuritySettings();
    CleanupStack::PushL( settings );
    settings->iImpl = CWEPSecuritySettingsImpl::NewL();
    CleanupStack::Pop( settings ); 
    return settings;    
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::~CWEPSecuritySettings
// ---------------------------------------------------------
//
EXPORT_C CWEPSecuritySettings::~CWEPSecuritySettings()
    {
    delete iImpl;
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::LoadL( TUint32 aIapId, 
                                           CCommsDatabase& aCommsDb )
    {
    iImpl->LoadL( aIapId, aCommsDb );
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SaveL( TUint32 aIapId, 
                                           CCommsDatabase& aCommsDb ) const
    {
    iImpl->SaveL( aIapId, aCommsDb );
    }
    

// ---------------------------------------------------------
// CWEPSecuritySettings::EditL
// ---------------------------------------------------------
//
EXPORT_C TInt CWEPSecuritySettings::EditL( CWEPSecuritySettingsUi& aUi,
                                           const TDesC& aTitle )
    {
    return aUi.iImpl->EditL( *iImpl, aTitle );
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::IsValid
// ---------------------------------------------------------
//
EXPORT_C TBool CWEPSecuritySettings::IsValid() const
    {
    return iImpl->IsValid();
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SetKeyDataL
// ---------------------------------------------------------
//
EXPORT_C TInt CWEPSecuritySettings::SetKeyDataL( const TInt aElement,
                                                 const TDesC& aKeyData,
                                                 const TBool aHex )
    {
    return iImpl->SetKeyDataL( aElement, aKeyData, aHex );
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::LoadL( TUint32 aIapId, 
                                           CMDBSession& aSession )
    {
    iImpl->LoadL( aIapId, aSession );
    }
    

// ---------------------------------------------------------
// CWEPSecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SaveL( TUint32 aIapId, 
                                           CMDBSession& aSession ) const
    {
    iImpl->SaveL( aIapId, aSession );
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SetKeyInUse
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SetKeyInUse( 
                                      CWEPSecuritySettings::TWEPKeyInUse aKey )
    {
    iImpl->SetKeyInUse( aKey );
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SetAuthentication
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SetAuthentication( 
                     CWEPSecuritySettings::TWEPAuthentication aAuthentication )
    {
    iImpl->SetAuthentication( aAuthentication );
    }

// End of File
