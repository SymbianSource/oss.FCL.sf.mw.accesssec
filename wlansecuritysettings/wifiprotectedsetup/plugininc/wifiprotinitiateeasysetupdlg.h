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
* Description: Declaration of class CWiFiProtInitiateEasySetupDlg.
*
*/

/*
* %version: tr1cfwln#6 %
*/

#ifndef C_WIFIPROTINITIATEEASYSETUPDLG_H
#define C_WIFIPROTINITIATEEASYSETUPDLG_H

// INCLUDES
#include <aknmessagequerydialog.h>

// CLASS DECLARATIONS
/**
 * Class implements a query dialog.
 */
NONSHARABLE_CLASS( CWiFiProtInitiateEasySetupDlg ) :
                                              public CAknMessageQueryDialog
    {
public:
    /**
    * Constructor the CWiFiProtInitiateEasySetupDlg class
    * @param aStatus Request status of the Active Runner
    */
    CWiFiProtInitiateEasySetupDlg( TRequestStatus& aStatus );

    /**
    * Destructor
    */
    virtual ~CWiFiProtInitiateEasySetupDlg();     

    /**
    * From @c MEikCommandObserver. 
    */
 
    /**
    * Tries to exit the dialog when the specified button is pressed, if this 
    * button should exit the dialog.
    *
    * See @c OkToExitL() to determine which buttons can exit the dialog.
    * 
    * This will fail if user exit is prevented by the 
    * @c EEikDialogFlagNoUserExit flag. If the @c EEikDialogFlagNotifyEsc flag
    * is not set and the dialog has been cancelled it immediately deletes 
    * itself.
    * 
    * @param aButtonId The id of the pressed button.
    */
    void TryExitL( TInt aButtonId );
        
private:

    /**
    * Exit function of CWiFiProtInitiateEasySetupDlg
    * @param aButtonId 
    * @return TBool exit or no
    */
    virtual TBool OkToExitL( TInt aButtonId );

    /**
    * PreLayoutDynInitL
    * @param    -
    */
    virtual void PreLayoutDynInitL();    
    
    /** 
    * From @c CCoeControl.
    *
    * Handles key events.
    * 
    * If a control wishes to process key events, it should implement this
    * function. The implementation must ensure that the function returns 
    * @c EKeyWasNotConsumed if it does not do anything in response to a 
    * key event, otherwise, other controls or dialogs may be prevented 
    * from receiving the key event. If it is able to process the event it 
    * should return @c EKeyWasConsumed.
    * 
    * @param aKeyEvent The key event.
    * @return Indicates whether or not the key event was used
    *         by this control. 
    */
    TKeyResponse OfferKeyEventL( const TKeyEvent& aKeyEvent, TEventCode );
    
private:
    // flag to indicate that the button group was changed
    // this is needed for changing softkey when selecting link
    TBool iButtonGroupPreviouslyChanged;
    // Client's request status, dialog completes it when it finished
    TRequestStatus& iRequestStatus;
    };

#endif  // C_WIFIPROTINITIATEEASYSETUPDLG_H

// End of File
