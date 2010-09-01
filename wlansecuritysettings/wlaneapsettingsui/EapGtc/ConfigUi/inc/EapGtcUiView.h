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
* Description: Header file of EAP GTC UI setting dialog
*
*/

/*
* %version: 16 %
*/

#ifndef _EAPGTCUIVIEW_H_
#define _EAPGTCUIVIEW_H_

// INCLUDES
#include <AknDialog.h>        
#include <eikspane.h>
#include <akntitle.h>
#include <aknsettingitemlist.h>
#include "EapGtcUi.hrh"
#include <aknnavi.h>
#include <eiklbo.h>


// FORWARD DECLARATIONS
class CAknSettingStyleListBox;
class CSettingsListBoxItemDrawer;
class CEapGtcSettingItemArray;
class CEapGtcUiConnection;
class CEapGtcUiGtcData;
class CEapGtcUiDataConnection;


// CLASS DECLARATION

/**
*  Settings dialog class definition
*/
class CEapGtcUiDialog : public CAknDialog,
                        public MEikListBoxObserver
    {
    public:
        CEapGtcUiDialog( CEapGtcUiConnection* aConnection, 
                         TInt& aButtonId );

        ~CEapGtcUiDialog();
 
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

    private:
        void InitializeSettingsL();
        void DrawSettingsListL();
        void ChangeTitleL( TBool aIsStarted );
        void ShowSettingPageL( TInt aCalledFromMenu ); 
        void ProcessCommandL( TInt aCommand );
        void SaveSettings();

        void GetHelpContext( TCoeHelpContext& aContext ) const;

        /**
        * Initialize menu pane.
        * @param aResourceId Menu pane resource id.
        * @param CEikMenuPane Menu pane.
        */
        void DynInitMenuPaneL( TInt aResourceId, CEikMenuPane* aMenuPane );


    private:
        CEapGtcUiConnection* iConnection;
        CEapGtcUiGtcData* iUiData;
        CEapGtcUiDataConnection* iDataConnection;
        CEapGtcSettingItemArray* iSettingArray;
        CAknSettingStyleListBox* iSettingListBox;
        CSettingsListBoxItemDrawer* iSettingListItemDrawer;
        CAknNavigationControlContainer* iNaviPane;
        CAknNavigationDecorator* iNaviDecorator;
        HBufC* iPreviousText;
        TInt* iButtonId;
        
        // Tells the status of UI construction. TRUE if UI construction is completed.
		TBool iIsUIConstructionCompleted;
    };

#endif // _EAPGTCUIVIEW_H_

//  End of File