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
* Description: Header file of PAP UI setting dialog
*
*/



#ifndef _PAPUIVIEW_H_
#define _PAPUIVIEW_H_

// INCLUDES
#include <AknDialog.h>        // AVKON components
#include <eikspane.h> // For changing status pane 
#include <akntitle.h>
#include <aknnavi.h>
#include <aknsettingitemlist.h>
#include <aknlists.h>
#include <aknselectionlist.h>
#include <eiklbo.h>
#include "papui.hrh"
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiTlsPeapData.h>

// FORWARD DECLARATIONS
class CAknSettingStyleListBox;
class CSettingsListBoxItemDrawer;
class CPapSettingItemArray;


// CLASS DECLARATION

/**
*  Settings dialog class definition
*/
class CPapUiDialog : public CAknDialog,
                     public MEikListBoxObserver
    {
    public:
        CPapUiDialog( CEapTlsPeapUiConnection* aConnection, 
                              TInt& aButtonId );

        ~CPapUiDialog();

        /**
        * Create and launch dialog.
        * @param aResourceId The resource ID of the dialog to load.
        * @return The ID of the button that closed the dialog
        */
        TInt ConstructAndRunLD( TInt aResourceId );
        
                
    public: // From MEikListBoxObserver
        
        /**
        * Handles list box events.
        * @param aListBox   The originating list box.
        * @param aEventType A code for the event.
        */
        void HandleListBoxEventL( CEikListBox* aListBox, TListBoxEvent aEventType );                
        
        
    protected:
        void PreLayoutDynInitL();
        TBool OkToExitL( TInt aButtonId );
        void ProcessCommandL( TInt aCommand );

    private:
        void ChangeTitleL( TBool aIsStarted );
        void DrawSettingsListL();
        void ShowSettingPageL( TInt aCalledFromMenu );
        void ShowUsernameSettingPageL();
        void ShowPasswordSettingPageL(); 
        void GetHelpContext( TCoeHelpContext& aContext ) const;

        /**
        * Initialize menu pane.
        * @param aResourceId Menu pane resource id.
        * @param CEikMenuPane Menu pane.
        */
        void DynInitMenuPaneL( TInt aResourceId, CEikMenuPane* aMenuPane );
        
        /**
        * Copy the setting data to the eapol db data pointer.
        */
        void UpdateEapolData();


    private:
        CEapTlsPeapUiConnection* iConnection;
        CEapTlsPeapUiDataConnection* iDataConnection;        
        CEapTlsPeapUiTlsPeapData* iUiData;
        CPapSettingItemArray* iSettingArray;
        CAknSettingStyleListBox* iSettingListBox;
        CAknNavigationControlContainer* iNaviPane;
        CAknNavigationDecorator* iNaviDecorator;        
        HBufC* iPreviousText;
        TInt* iButtonId;
                
        // Temporary UI data as shown on the Settings UI
        TBuf<KPapUsernameMaxLength> iSettingUsername;
        TBool iSettingPwPrompt;
        TBuf<KPapPasswordMaxLength> iSettingPassword;
        
        
        // Tells the status of UI construction. TRUE if UI construction is completed.
		TBool iIsUIConstructionCompleted;
		
		TBool iUsernameCancelled;
    };


#endif // _PAPUIVIEW_H_

//  End of File
