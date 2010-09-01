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
* Description: Implementation of class CWPASecuritySettings.     
*
*/

/*
* %version: tr1cfwln#18 %
*/

// INCLUDE FILES

#include "WPASecuritySettingsImpl.h"
#include "WPASecuritySettingsUiImpl.h"

#include <WPASecuritySettingsUI.h>



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettings::NewL
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettings* CWPASecuritySettings::NewL( 
                                                TSecurityMode aSecurityMode )
    {
    CWPASecuritySettings* settings = new ( ELeave ) CWPASecuritySettings();
    CleanupStack::PushL( settings );
    settings->iImpl = CWPASecuritySettingsImpl::NewL( aSecurityMode );
    CleanupStack::Pop( settings ); 
    return settings;    
    }


// ---------------------------------------------------------
// CWPASecuritySettings::~CWPASecuritySettings
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettings::~CWPASecuritySettings()
    {
    delete iImpl;
    }


// ---------------------------------------------------------
// CWPASecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::LoadL( TUint32 aIapId, 
                                           CCommsDatabase& aCommsDb )
    {
    iImpl->LoadL( aIapId, aCommsDb );
    iImpl->SetIapId( aIapId );
    }


// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::SaveL( TUint32 aIapId, 
                                           CCommsDatabase& aCommsDb, 
                                           TTypeOfSaving aTypeOfSaving, 
                                           TUint32 aOldIapId ) const
    {
    iImpl->SaveL( aIapId, aCommsDb, aTypeOfSaving, aOldIapId );
    }
    

// ---------------------------------------------------------
// CWPASecuritySettings::EditL
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::EditL( CWPASecuritySettingsUi& aUi,
                                           const TDesC& aTitle )
    {
    return aUi.iImpl->EditL( *iImpl, aTitle );
    }


// ---------------------------------------------------------
// CWPASecuritySettings::DeleteL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::DeleteL( TUint32 aIapId ) const
    {
    iImpl->DeleteL( aIapId );
    }


// ---------------------------------------------------------
// CWPASecuritySettings::IsValid
// ---------------------------------------------------------
//
EXPORT_C TBool CWPASecuritySettings::IsValid() const
    {
    return iImpl->IsValid();
    }


// ---------------------------------------------------------
// CWPASecuritySettings::SetWPAPreSharedKey
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::SetWPAPreSharedKey( 
                                                const TDesC& aPreSharedKey )
    {
    return iImpl->SetWPAPreSharedKey( aPreSharedKey );
    }


// ---------------------------------------------------------
// CWPASecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::LoadL( TUint32 aIapId, 
                                           CMDBSession& aSession )
    {
    iImpl->LoadL( aIapId, aSession );
    iImpl->SetIapId( aIapId );
    }
    
    
// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::SaveL( TUint32 aIapId,
                                           CMDBSession& aSession,
                                           TTypeOfSaving aTypeOfSaving,
                                           TUint32 aOldIapId ) const
    {
    iImpl->SaveL( aIapId, aSession, aTypeOfSaving, aOldIapId );
    }


// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::SetWPAEnabledEAPPlugin( 
                                            const TDesC8& aEnabledPluginList )
    {
    return iImpl->SetWPAEnabledEAPPlugin( aEnabledPluginList );
    }

// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::SetWPADisabledEAPPlugin( 
                                            const TDesC8& aDisabledPluginList )
    {
    return iImpl->SetWPADisabledEAPPlugin( aDisabledPluginList );
    }
        

// End of File
