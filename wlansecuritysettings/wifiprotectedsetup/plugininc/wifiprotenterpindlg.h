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
* Description: Implementation of class CWiFiProtEnterPinDlg.
*
*/

/*
* %version: tr1cfwln#9 %
*/

#ifndef C_WIFIPROTENTERPINDLG_H
#define C_WIFIPROTENTERPINDLG_H

// INCLUDES
#include <AknQueryDialog.h>

// FORWARD DECLARATIONS
class MActiveRunnerCallback;

// CLASS DECLARATIONS

/**
 * Class implements a query dialog.
 */
NONSHARABLE_CLASS( CWiFiProtEnterPinDlg ) : public CAknQueryDialog
    {
public:
    /**
    * Constructor of the CWiFiProtEnterPinDlg class
    * @param MActiveRunnerCallback& aActiveRunnerCallback callback to
    * notify the client of user response
    * Active Runner gets completed when the dialog finishes 
    */
    CWiFiProtEnterPinDlg( MActiveRunnerCallback& aActiveRunnerCallback );

   
    /**
    * Destructor
    */
    virtual ~CWiFiProtEnterPinDlg();   
    
    /**
    * From @c MEikCommandObserver. 
    *
    * Acts on the menu selection if menu is showing 
    * @param aCommandId id of the command to process
    *
    * Responds to @c EAknSoftkeyOk and @c EAknSoftkeyYes and 
    * @c EAknSoftkeyDone and @c EWiFiSoftkeyContinue
    * @c EAknSoftkeyEmpty commands. 
    *
    * @since S60 3.0 
    */
    void ProcessCommandL( TInt aCommandId );  
    
    /*
    * Removes Cancel softkey
    */
    void RemoveCancel();    

private:

    /**
    * Exit function the CWiFiProtConfirmationNoteDlg
    * @param aButtonId 
    * @return TBool exit or no
    */
    virtual TBool OkToExitL( TInt aButtonId );

    /**
    * PreLayoutDynInitL
    * @param    -
    */
    virtual void PreLayoutDynInitL();    
private:
    // Client's request status, dialog completes it when it finished
    MActiveRunnerCallback& iActiveRunnerCallback;
    };


#endif  // C_WIFIPROTENTERPINDLG_H

// End of File
