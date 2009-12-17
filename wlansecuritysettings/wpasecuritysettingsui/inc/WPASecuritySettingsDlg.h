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
* Description: Declares dialog. 
*
*/


#ifndef WPA_SECURITY_SETTINGS_DLG_H
#define WPA_SECURITY_SETTINGS_DLG_H


// ENUMERATIONS

// Members to be showed in the setting pages
enum TWpaMember
    {
    EWpaMode,           // WPA mode
    EWpaEapConfig,      // EAP Plugin configuration
    EWpaWpa2Only,       // Wpa2 only mode
    EWpaPreSharedKey    // Pre-shared key
    };


// INCLUDES
#include <AknDialog.h>
#include <eiklbo.h>
#include <aknlists.h>
#ifndef SYMBIAN_ENABLE_SPLIT_HEADERS
#include <commsdat.h>
#else
#include <commsdat.h>
#include <commsdat_partner.h>
#endif
#include "WPASecuritySettingsImpl.h"

// FORWARD DECLARATIONS
class CAknTitlePane;
class CWPASecuritySettingsImpl;
class CEAPPluginConfigurationIf;


// CLASS DECLARATION
/**
* CWPASecuritySettingsDlg dialog class
*/
NONSHARABLE_CLASS( CWPASecuritySettingsDlg ) : public CAknDialog, 
                                               public MEikListBoxObserver
    {

    public: // Constructors and destructor

        /**
        * Create and launch dialog.
        * @param aSecuritySettings Security settings
        * @param aTitle Title of the dialog
        * @return The ID of the button that closed the dialog
        */
        TInt ConstructAndRunLD( CWPASecuritySettingsImpl* aSecuritySettings,
                                const TDesC& aTitle );


        /**
        * Two-phase construction.
        * @param aEventStore A reference to hold the events happened
        * @param aIapId Id of the IAP.
        * @param aPlugin The EAP Configuration plugin.
        * @return The constructed CWPASecuritySettingsDlg object.
        */
        static CWPASecuritySettingsDlg* NewL( TInt& aEventStore, 
                                          const TUint32 aIapId,
                                          CEAPPluginConfigurationIf* aPlugin );

        /**
        * Destructor.
        */
        ~CWPASecuritySettingsDlg();


	protected:
        /**
        * Constructor.
        * @param aEventStore A reference to hold the events happened
        * @param aIapId Id of the IAP.
        * @param aPlugin The EAP Configuration plugin.
        */
        CWPASecuritySettingsDlg( TInt& aEventStore, const TUint32 aIapId,
                                 CEAPPluginConfigurationIf* aPlugin );


    public:     // Functions from base classes
        /**
        * Handle key events. 
        * @param aKeyEvent: key event
        * @param aType: type of event
        * @return The key response, if it was consumed or not. 
        */
		TKeyResponse OfferKeyEventL( const TKeyEvent& aKeyEvent,
                                     TEventCode aType );

	private:    // Functions from base classes

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
        * Handles list box events.
        * @param aListBox   The originating list box. 
        * @param aEventType A code for the event.
        */
		void HandleListBoxEventL( CEikListBox* aListBox, 
                                  TListBoxEvent aEventType );

        /**
        * Get help context.
        * @param aContext Help context is returned here.
        */
        void GetHelpContext( TCoeHelpContext& aContext ) const;

        /**
        * Initialize menu pane.
        * @param aResourceId Menu pane resource id.
        * @param CEikMenuPane Menu pane.
        */
        void DynInitMenuPaneL( TInt aResourceId, CEikMenuPane* aMenuPane );


    protected:  // New functions

        /**
        * Handles listbox data change
        */
        void HandleListboxDataChangeL();


        /**
        * Fills up the listbox with data
        * @param aItemArray Array where to add the elements
        * @param arr        Array to be used as list elements
        * @param aRes       Array of resource IDs to be used for the 
        *                   elements of arr
        */
        void FillListWithDataL( CDesCArrayFlat& aItemArray, 
                                const TWpaMember& arr, const TInt* aRes );


        /**
        * Updates one 'textual' listbox item for the given member
        * @param aMember    Value specifying which member has to be added to 
        *                   the list
        * @param aRes       Resource ID for the 'title text' for this member
        * @param aPos       The current position of the item in the list
        */
        void UpdateTextualListBoxItemL( TWpaMember aMember, TInt aRes, 
                                        TInt aPos );


        /**
        * Creates one 'textual' listbox item for the given member
        * @param aMember    Value specifying which member has to be added to
        *                   the list
        * @param aRes       Resource ID for the 'title text' for this member
        * @return The created listbox item text.
        */
        HBufC* CreateTextualListBoxItemL( TWpaMember aMember, TInt aRes );


        /**
        * Changes one setting. The setting, which is
        * highlighted as current in the listbox is changed.
        * @param aQuick ETrue if the setting is "two-choices", and can be 
        *               automatically changed, without showing the list of 
        *               elements
        */
        void ChangeSettingsL( TBool aQuick );


        /**
        * Shows a popup setting page (radio buttons) for the given member
        * @param aDataMember    The member which needs to be changed
        * @return   A boolean indicating whether the current setting
        *           has been changed or not.
        */
        TBool ShowPopupSettingPageL( TWpaMember aDataMember );


        /**
        * Shows a popup text setting page for the given member
        * @return   A boolean indicating whether the current setting
        *           has been changed or not.
        */
        TBool ShowPopupTextSettingPageL();


        /**
        * Fills up a pop-up radio button setting page with the currently
        * valid and available choices for the given member.
        * @param aData      The member whose new setting is needed
        * @param aCurrvalue The current value of the setting
        * @return   An array of choices for the given member, pushed to the 
        *           CleanupStack.
        */
        CDesCArrayFlat* FillPopupSettingPageLC( TWpaMember aData,
                                                TInt& aCurrvalue );


        /**
        * Updates the given member's data with the new setting from the setting
        * page.
        * @param aData      The member to update
        * @param aCurrvalue The new value
        * @return   A boolean indicating if the value is actually changed
        */
        TBool UpdateFromPopupSettingPage( TWpaMember aData, TBool aCurrvalue );


        /**
        * Cleanup for the iEapConfigActive semaphore flag
        * @since S60 5.0
        * @param aPtr Pointer to this class
        */
        static void ResetEapConfigFlag( TAny* aPtr );
        
        /**
        * @see CEikDialog
        */
        void HandleDialogPageEventL( TInt aEventID );

    private: //data

        // Stores the name of the connection, to be showed as the title.
      	TBuf<CommsDat::KMaxTextLength> iConnectionName;

        // Title pane. Not owned.
        CAknTitlePane* iTitlePane;

        // Pointer to the old title. Owned.
        HBufC* iOldTitleText;

        // Owned through resources, destroyed automatically by the dialog.
        CAknSettingStyleListBox* iList;

        // Array of the items. Not owned.
        CDesCArrayFlat* iItemArray;

        // Fields of the main view. Not owned.
        TWpaMember* iFieldsMain;

        // Titles of the main view. Not owned.
        TInt* iTitlesMain;

        // Pointer to the WPA Security Settings. Not owned.
        CWPASecuritySettingsImpl* iSecuritySettings;

        // To hold the events. Not owned.
        TInt* iEventStore;
        
        // The Id of the AP.
        TUint32 iIapId;

        // The EAP Configuration plugin. Not owned.
        CEAPPluginConfigurationIf* iPlugin;
        
        // Indicates whether the EAP plugin configuration is active
        TBool iEapConfigActive;
        
        TBuf8<KWLANEAPLISTLENGTH> iEnabledPluginList;
        TBuf8<KWLANEAPLISTLENGTH> iDisabledPluginList;
    };


#endif      // WPA_SECURITY_SETTINGS_DLG_H

// End of File
