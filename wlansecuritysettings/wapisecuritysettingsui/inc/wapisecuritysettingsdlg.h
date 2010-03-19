/*
* ============================================================================
*  Name     : wapisecuritysettingsdlg.h
*  Part of  : WAPI Security Settings UI
*
*  Description:
*     Declares dialog.
*  Version: %version:  7 %
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

#ifndef WAPI_SECURITY_SETTINGS_DLG_H
#define WAPI_SECURITY_SETTINGS_DLG_H


// INCLUDES
#include <eiklbo.h>
#include <AknDialog.h>
#include <aknlists.h>
#include <WapiCertificates.h>
#include "wapisecuritysettingsdefs.h"

// FORWARD DECLARATIONS
class CAknTitlePane;

// CLASS DECLARATION
/**
* CWAPISecuritySettingsDlg dialog class
*/
NONSHARABLE_CLASS( CWAPISecuritySettingsDlg ) : public CAknDialog, 
                                               public MEikListBoxObserver
    {
    public: // Constructors and destructor

        /**
        * Create and launch dialog.
        * @param aSecuritySettings Security settings
        * @param aTitle Title of the dialog
        * @return The ID of the button that closed the dialog
        */
        TInt ConstructAndRunLD( CWAPISecuritySettingsImpl* aSecuritySettings,
                                const TDesC& aTitle );


        /**
        * Two-phase construction.
        * @param aEventStore A reference to hold the events happened
        * @return The constructed CWAPISecuritySettingsDlg object.
        */
        static CWAPISecuritySettingsDlg* NewL( TInt& aEventStore );


        /**
        * Destructor.
        */
        ~CWAPISecuritySettingsDlg();

        
    public: //Types
         
        enum TWapiMember
            {
            EWapiAuth,
            EWapiUserCert,
            EWapiCACert,
            EWapiPSKFormat,
            EWapiPSK
            };   
          
    protected:
        /**
        * Constructor.
        * @param aEventStore A reference to hold the events happened
        */

	    CWAPISecuritySettingsDlg( TInt& aEventStore );

	    
    public: // Functions from base classes
        /**
        * Handle key events. 
        * @param aKeyEvent: key event
        * @param aType: type of event
        * @return The key response, if it was consumed or not. 
        */
		TKeyResponse OfferKeyEventL( const TKeyEvent& aKeyEvent,
                                     TEventCode aType );

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
        * @param aLength    The number of elements in the above array
        * @param aRes       Array of resource IDs to be used for the 
        *                   elements of arr
        */
        void FillListWithDataL( CDesCArrayFlat& aItemArray, 
                                const TWapiMember& arr, 
                                TInt aLength,
                                const TInt* aRes );


        /**
        * Updates one listbox item for the given member
        * @param aMember    Value specifying which member has to be added to 
        *                   the list
        * @param aRes       Resource ID for the 'title text' for this member
        * @param aPos       The current position of the item in the list
        */
        void UpdateListBoxItemL( TWapiMember aMember, 
                                 TInt aRes, TInt aPos );


        /**
        * Creates one 'textual' listbox item for the given member
        * @param aMember    Value specifying which member has to be added to
        *                   the list
        * @param aRes       Resource ID for the 'title text' for this member
        * @return The created listbox item text.
        */
        HBufC* CreateTextualListBoxItemL( TWapiMember aMember, 
                                          TInt aRes );

        HBufC* CWAPISecuritySettingsDlg::FormatCertTextualListBoxItemL( 
                                                    TWapiMember aMember, TInt aRes );
        /**
        * Changes one setting. The setting, which is
        * highlighted as current in the listbox is changed.
        */
        void ChangeSettingsL();


        /**
        * Shows a popup setting page (radio buttons) for the given member
        * @param aDataMember    The member which needs to be changed
        * @return   A boolean indicating whether the current setting
        *           has been changed or not.
        */
        TBool   ShowPopupSettingPageL( TWapiMember aDataMember );

        /**
        * Shows a text setting page for setting PSK key.
        * @return   A boolean indicating whether the current setting
        *           has been changed or not.
        */
        TBool ShowPopupPSKSettingPageL();

        /**
        * Fills up a pop-up radio button setting page with the currently
        * valid and available choices for the given member.
        * @param aData      The member whose new setting is needed
        * @param aCurrvalue The current value of the setting
        * @return   An array of choices for the given member, pushed to the 
        *           CleanupStack.
        */
        CDesCArrayFlat* FillPopupSettingPageLC( TWapiMember aData,
                                                TInt& aCurrvalue );


        /**
        * Updates the given member's data with the new setting from the setting
        * page.
        * @param aData      The member to update
        * @param aCurrvalue The new value
        * @return An integer boolean indicating if the value is actually changed
        */
        TBool UpdateFromPopupSettingPage( TWapiMember aData, 
                                          TInt aCurrvalue );
        
    private: //data

        // Stores the name of the connection, to be showed as the title.
      	TBuf<KMaxTextLength> iConnectionName;

        // Title pane. Not owned.
        CAknTitlePane* iTitlePane;

        // Pointer to the old title. Owned.
        HBufC* iOldTitleText;

       // Owned through resources, destroyed automatically by the dialog.
        CAknSettingStyleListBox* iList;

        // Array of the items. Not owned.
        CDesCArrayFlat* iItemArray;

        // Fields of the main view. Not owned.
        TWapiMember* iFieldsMain;

        // Titles of the main view. Not owned.
        TInt* iTitlesMain;

        // Pointer to the WAPI Security Settings. Not owned.
        CWAPISecuritySettingsImpl* iSecuritySettings;

        // To hold the events. Not owned.
        TInt* iEventStore;

        //Pointers to certificate arrays. Not owned.
        RArray<TBuf<KMaxLabelLength> >* iUserCertificates; 
        RArray<TBuf<KMaxLabelLength> >* iCACertificates;
        
    };


#endif      // WAPI_SECURITY_SETTINGS_DLG_H

// End of File
