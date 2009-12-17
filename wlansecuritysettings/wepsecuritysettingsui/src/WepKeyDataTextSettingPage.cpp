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
* Description: Implementation of CWEPKeyDataTextSettingPage.
*
*/


// INCLUDE FILES

//#include <fepbase.h>

#include <WEPSecuritySettingsUI.rsg>

#include "WepKeyDataTextSettingPage.h"



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPKeyDataTextSettingPage::CWEPKeyDataTextSettingPage
// ---------------------------------------------------------
//
CWEPKeyDataTextSettingPage::CWEPKeyDataTextSettingPage( TDes& aText,
                            TInt aMaxLength, 
                            CWEPSecuritySettings::TWEPKeyFormat aWEPKeyFormat )
:CAknTextSettingPage( R_TEXT_SETTING_PAGE_KEY_DATA, aText, 
                      EAknSettingPageNoOrdinalDisplayed ),
 iLengthOfKeyData( aMaxLength ),
 iWEPKeyFormat( aWEPKeyFormat )
    {
    }



// ---------------------------------------------------------
// CWEPKeyDataTextSettingPage::ConstructL
// ---------------------------------------------------------
//
void CWEPKeyDataTextSettingPage::ConstructL()
    {
    CAknTextSettingPage::ConstructL();

	CEikEdwin* editor = TextControl();

	editor->SetMaxLength( iLengthOfKeyData );

    if ( iWEPKeyFormat == CWEPSecuritySettings::EAscii )
        {
        editor->SetOnlyASCIIChars( ETrue );
    	editor->SetAknEditorCase( EAknEditorLowerCase );
        }
    else
        {
    	editor->SetAknEditorCase( EAknEditorUpperCase );
	    editor->SetAknEditorSpecialCharacterTable( 0 );
        }   
    }


// End of File
