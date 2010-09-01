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
* Description: Header file of EAP PEAP UI setting dialog
*
*/

/*
* %version: 21 %
*/

#ifndef _EAPPEAPUIVIEW_H_
#define _EAPPEAPUIVIEW_H_

// INCLUDES
#include <AknDialog.h>        // AVKON components
#include <eikspane.h> // For changing status pane 
#include <akntitle.h>
#include <aknsettingitemlist.h>
#include <aknlists.h>
#include <aknselectionlist.h>
#include <eiklbo.h>
#include "EapPeapUi.hrh"
#include <EapTlsPeapUiCipherSuite.h>
#include <EapTlsPeapUiEapType.h>
#include <EapTlsPeapUiCertificate.h>
#include <AbsEapTlsPeapUiCertificates.h>
#include <EapTlsPeapUiConnection.h>
#include <EapTlsPeapUiDataConnection.h>
#include <EapTlsPeapUiTlsPeapData.h>

// FORWARD DECLARATIONS
class CAknSettingStyleListBox;
class CSettingsListBoxItemDrawer;
class CEapPeapSettingItemArray;


// CLASS DECLARATION

/**
*  Settings dialog class definition
*/
class CEapPeapUiDialog : public CAknDialog, 
                         public MEapTlsPeapUiCertificates,
                         public MEikListBoxObserver
    {
    public:
        CEapPeapUiDialog( CEapTlsPeapUiConnection* aConnection, 
                          TIndexType aIndexType, TInt aIndex, 
                          TInt& aButtonId );

        ~CEapPeapUiDialog();

        /**
        * Create and launch dialog.
        * @param aResourceId The resource ID of the dialog to load.
        * @return The ID of the button that closed the dialog
        */
        TInt ConstructAndRunLD( TInt aResourceId );
        
        /**
        * Chain into key event handler.
        * @param aKeyEvent The event.
        * @param aType The type of key event.
        * @return Was the key consumed or not.
        */
        TKeyResponse OfferKeyEventL(const TKeyEvent& aKeyEvent,
                                          TEventCode aType);
                                          
        
    public: // From MEikListBoxObserver
        
        /**
        * Handles list box events.
        * @param aListBox   The originating list box.
        * @param aEventType A code for the event.
        */
        void HandleListBoxEventL( CEikListBox* aListBox, TListBoxEvent aEventType );
        
    
    public: // From CEikDialog
            
        /**
        * @see CEikDialog
        */
        void HandleDialogPageEventL( TInt aEventID );
                                          

    protected:
        void PreLayoutDynInitL();
        void PostLayoutDynInitL();
        TBool OkToExitL( TInt aButtonId );
        void ProcessCommandL( TInt aCommand );
        void PageChangedL( TInt aPageId );

    private:
        void ChangeTitleL( TBool aIsStarted );
        void DrawSettingsListL();
        void ShowSettingPageL( TInt aCalledFromMenu ); 
        void MoveEapTypeL( TInt aOldPos, TInt aNewPos );
        void DrawEapListL(TInt aWantedIndex);
        TInt ShowRadioButtonSettingPageL( TInt aTitle, CDesCArrayFlat* aValues,
                                          TInt aCurrentItem );
        void DrawCipherSuitesL();
        void CompleteReadCertificates( const TInt aResult );
        void CompleteUiConstructionL();
        TInt CheckActiveUserCertificate();
        TInt CheckActiveCaCertificate();
        void UserCertificateHouseKeeping( TInt aSelected );
        void CaCertificateHouseKeeping( TInt aSelected );
        void CreateEapTypeDataBaseL();    
        void SetCipherIconsL();
        void SetEapIconsL();
        TUint GetEnabledEapTypeCount();
        void GetHelpContext(TCoeHelpContext& aContext) const;
            
        void GetFullCertLabelL( const SCertEntry& aCert, TDes& aFullLabel );

        /**
        * Initialize menu pane.
        * @param aResourceId Menu pane resource id.
        * @param CEikMenuPane Menu pane.
        */
        void DynInitMenuPaneL( TInt aResourceId, CEikMenuPane* aMenuPane );

        void ConfigureL( TBool aQuick );
        
    private:
        CEapTlsPeapUiConnection* iConnection;
        CEapTlsPeapUiDataConnection* iDataConnection;
        CEapTlsPeapUiCipherSuites* iCipherSuites;
        CEapTlsPeapUiCertificates* iCertificates;
        
        CEapTlsPeapUiTlsPeapData* iUiData;
        CArrayFixFlat<TEapTlsPeapUiCipherSuite>* iUiCipherSuites;
        CArrayFixFlat<TEapTlsPeapUiCertificate>* iUiUserCertificates;
        CArrayFixFlat<TEapTlsPeapUiCertificate>* iUiCACertificates;
        CArrayFixFlat<TEapTlsPeapUiEapType>* iUiEapTypes;
                                
        CAknSingleNumberStyleListBox* iUserCertificateListBox;
        CAknSingleNumberStyleListBox* iCaCertificateListBox;
        CAknSingleNumberStyleListBox* iCipherSuiteListBox;
        CAknSingleNumberStyleListBox* iEapTypesListBox;
        CEapPeapSettingItemArray* iSettingArray;
        CAknSettingStyleListBox* iSettingListBox;
        CDesCArray* iEapTypeViewArray;
        CDesCArray* iCipherSuitesViewArray;
        CEapTlsPeapUiEapTypes* iEapTypes;
        TIndexType iIndexType; 
        TInt iIndex;
        HBufC* iPreviousText;
        TInt* iButtonId;
        
        // Tells the status of UI construction. TRUE if UI construction is completed.
		TBool iIsUIConstructionCompleted;
		
		// For exiting dialog
		TBool iExiting;
    };


#endif // _EAPPEAPUIVIEW_H_

//  End of File
