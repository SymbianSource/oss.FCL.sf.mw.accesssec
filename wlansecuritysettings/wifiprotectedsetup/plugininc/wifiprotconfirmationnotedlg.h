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
* Description: Implementation of class CWiFiProtConfirmationNoteDlg.
*
*/


#ifndef C_WIFIPROTCONFIRMATIONNOTEDLG_H__
#define C_WIFIPROTCONFIRMATIONNOTEDLG_H__

// INCLUDES
#include <AknQueryDialog.h>

// CLASS DECLARATIONS

/**
 * Class implements a query dialog.
 */
NONSHARABLE_CLASS( CWiFiProtConfirmationNoteDlg ) : public CAknQueryDialog
    {
public:
    /**
    * Constructor the CWiFiProtConfirmationNoteDlg class
    * @param aStatus TRequestStatus of the client,
    * gets completed when dialog finishes 
    * @return -
    */
    CWiFiProtConfirmationNoteDlg( TRequestStatus& aStatus );
   
    /**
    * Destructor
    */
    virtual ~CWiFiProtConfirmationNoteDlg();   
    
    /**
    * From @c MEikCommandObserver. 
    *
    * Acts on the menu selection if menu is showing 
    * @param aCommandId id of the command to process
    *
    * Responds to @c EAknSoftkeyOk and @c EAknSoftkeyYes and 
    * @c EAknSoftkeyDone and @c EWiFiSoftkeyContinue commands. 
    *
    * @since S60 3.0 
    */
    void ProcessCommandL( TInt aCommandId );  

private:

    /**
    * Exit function the CWiFiProtConfirmationNoteDlg
    * @param aButtonId Button id which is checked before
    * deciding to exit or not
    * @return TBool exit or no
    */
    virtual TBool OkToExitL( TInt aButtonId );

    /**
    * PreLayoutDynInitL
    */
    virtual void PreLayoutDynInitL(); 
       
private:
    // Client's request status, dialog completes it when it finished
    TRequestStatus& iRequestStatus;
    };


#endif  // C_WIFIPROTCONFIRMATIONNOTEDLG_H__

// End of File
