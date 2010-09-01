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
* Description: Header file of PAP UI password setting item
*
*/

/*
* %version: 5 %
*/

#ifndef _PAPUIPWSETTINGITEM_H_
#define _PAPUIPWSETTINGITEM_H_

// INCLUDES
#include <aknsettingitemlist.h>

// FORWARD DECLARATIONS
class CPapSettingItemArray;

// CLASS DECLARATION

/**
*  Password setting item class definition
*/
class CPapUiPwSettingItem : public CAknPasswordSettingItem
    {
    public:
    
        CPapUiPwSettingItem( TInt aIdentifier,
            enum TAknPasswordSettingItemMode aMode,
            TDes &aPassword,
            CPapSettingItemArray* aParent );

        ~CPapUiPwSettingItem();
        
                
    public: // From CAknSettingItem
        
        /**
        * Handles setting page events.
        * @param aSettingPage  The originating setting page.
        * @param aEventType A code for the event.
        */
        void HandleSettingPageEventL(
            CAknSettingPage *aSettingPage, TAknSettingPageEvent aEventType );
            
    public: // new
    
        /**
        * Deletes the password.
        */
        void DeletePasswordL();
            
        
    private:
        
        // Reference, not owned
        CPapSettingItemArray* iParent;		
    };


#endif // _PAPUIPWSETTINGITEM_H_

//  End of File
