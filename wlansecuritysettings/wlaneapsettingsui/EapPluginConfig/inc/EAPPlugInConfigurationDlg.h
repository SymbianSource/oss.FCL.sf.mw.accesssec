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
* Description: Declares dialog
*
*/

/*
* %version: 17 %
*/

#ifndef __EAPPLUGINCONFIGURATIONDLG_H__
#define __EAPPLUGINCONFIGURATIONDLG_H__


// INCLUDES
#include <aknselectionlist.h>
#include <commdb.h>

#include "EAPPluginList.h"


// FORWARD DECLARATIONS
class CAknTitlePane;
class CEAPPluginConfigurationModel;


// CONSTANTS
/**
* Maximum length of a SSID in BYTES
*/
const TUint8 KMaxSSIDLength = 32;


// CLASS DECLARATION
/**
* CEAPPluginConfigurationDlg dialog class
*/
class CEAPPluginConfigurationDlg : public CAknSelectionListDialog
    {
    public: // Constructors and destructor

        /**
        * Constructor.
        * @param aButtonId Button used to close the dialog
        * @param aModel UI model.
        */
        CEAPPluginConfigurationDlg( TInt& aButtonId,
                                 CEAPPluginConfigurationModel& aModel,
                                 const TUint32 iIapId );
        /**
        * Create and launch dialog.
        * @param aPlugins   Plugin list
        * @param aTitle Title of the dialog
        * @return The ID of the button that closed the dialog
        */
        TInt ConstructAndRunLD( const REAPPluginList& aPlugins,
                                const TDesC& aTitle );


        /**
        * Destructor.
        */
        ~CEAPPluginConfigurationDlg();
        
        /**
        * Handles list box events.
        * @param aListBox   The originating list box.
        * @param aEventType A code for the event.
        */
        void HandleListBoxEventL( CEikListBox* aListBox, TListBoxEvent aEventType );


    private:

        /**
        * This function is called by the dialog framework before the dialog is 
        * sized and laid out.
        */
        virtual void PreLayoutDynInitL();


        /**
        * Handles a dialog button press for the specified button 
        * @param aButtonId  The ID of the button that was activated.
        * @return   ETrue to validate and exit the dialog, 
        *           EFalse to keep the dialog active
        */
        TBool OkToExitL( TInt aButtonId );


        /**
        * Processes user commands.
        * @param aCommandId ID of the command to respond to. 
        */
        virtual void ProcessCommandL( TInt aCommandId );


        /**
        * Get help context.
        * @param aContext Help context is returned here.
        */
        void GetHelpContext( TCoeHelpContext& aContext ) const;


        /**
        * Initialize menu pane.
        * @param aResourceId Menu pane resource id.
        * @param aMenuPane Menu pane.
        */
        void DynInitMenuPaneL( TInt aResourceId, CEikMenuPane* aMenuPane );


        /**
        * Catch offered key events.
        * @param aKeyEvent Key event
        * @param aModifiers Modifiers
        * @return EKeyWasConsumed or EKeyWasNotConsumed, appropriately.
        */
        TKeyResponse OfferKeyEventL( const TKeyEvent& aKeyEvent, 
                                     TEventCode aModifiers );

        void SetIconsL();
        void HandleResourceChange( TInt aType );
        
        /**
        * @see CEikDialog
        */
        void HandleDialogPageEventL( TInt aEventID );
        
        void ConfigureL( TBool aQuick );

    private: //data

        // Stores the name of the connection, to be showed as the title.
        TBuf<KMaxSSIDLength> iConnectionName;

        // Title pane. Not owned.
        CAknTitlePane* iTitlePane;

        // Pointer to the old title. Owned.
        HBufC* iOldTitleText;

        REAPPluginList iPlugins;
        
        TInt* iButtonId;

        // For base class, unused.
        TInt iDummy;

        // UI model. Not owned.
        CEAPPluginConfigurationModel* iModel;
        
        TUint32 iIapId;
        
        // For exiting dialog
        TBool iExiting;
        
    };


#endif      // __EAPPLUGINCONFIGURATIONDLG_H__

// End of File
