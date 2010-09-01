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
* Description: Stub Implementation of class CWAPISecuritySettings.     
*
*/

/*
* %version: 9 %
*/

// INCLUDE FILES
#include <e32base.h>
#include <wapisecuritysettingsui.h>


// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWAPISecuritySettings::NewL
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettings* CWAPISecuritySettings::NewL()
    {
    User::Leave(KErrNotSupported); 
    return NULL;
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::~CWAPISecuritySettings
// ---------------------------------------------------------
//
EXPORT_C CWAPISecuritySettings::~CWAPISecuritySettings()
    {
   
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::EditL
// ---------------------------------------------------------
//
EXPORT_C TInt CWAPISecuritySettings::EditL( CWAPISecuritySettingsUi& /* aUi */,
                                           const TDesC& /* aTitle */ )
    {
    return 0;
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::LoadL( TUint32 /* aIapRecordId */, CMDBSession& /* aSession  */)
    {
    
    }
    

// ---------------------------------------------------------
// CWAPISecuritySettings::IsValid
// ---------------------------------------------------------
//
EXPORT_C TBool CWAPISecuritySettings::IsValid( ) const

    {
    return EFalse;
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::SaveL( TUint32 /* aIapRecordId */, CMDBSession& /* aSession  */ ) const

    {
    
    }


// ---------------------------------------------------------
// CWAPISecuritySettings::SetPreSharedKey
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::SetPreSharedKeyL( const TWapiKeyFormat /* aKeyFormat */, const TDesC& /* aPreSharedKey */ )
    {
    }
	

// ---------------------------------------------------------
// CWAPISecuritySettings::DeleteAPSpecificDataL
// ---------------------------------------------------------
//
EXPORT_C void CWAPISecuritySettings::DeleteAPSpecificDataL( const TInt /* aId */)
    {
    
    }

// End of File
