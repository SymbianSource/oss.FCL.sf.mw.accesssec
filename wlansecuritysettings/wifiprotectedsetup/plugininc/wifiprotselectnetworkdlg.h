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
* Description: Definition of class CWiFiProtSelectNetworkDlg.
*
*/

/*
* %version: tr1cfwln#7 %
*/

#ifndef C_WIFIPROTSELECTNETWORKDLG_H
#define C_WIFIPROTSELECTNETWORKDLG_H

// INCLUDES
#include <aknlistquerydialog.h>

// CLASS DECLARATIONS
/**
 * Class implements a query dialog.
 */
NONSHARABLE_CLASS( CWiFiProtSelectNetworkDlg ) : public CAknListQueryDialog
    {
public:
    /**
    * Constructor the CWiFiProtSelectNetworkDlg class
    * @param aStatus TRequestStatus from activerunner
    * @param aSelected returned selection index
    * @param CDesCArrayFlat* aItems listbox items, ownership passed
    * @param CArrayPtr<CGulIcon>* aIcons listbox icons, ownership passed    
    * @return -
    */
    CWiFiProtSelectNetworkDlg( TRequestStatus& aStatus , TInt& aSelected ,
                               CDesCArrayFlat* aItems,
                               CArrayPtr<CGulIcon>* aIcons );

    /**
    * Destructor
    */
    virtual ~CWiFiProtSelectNetworkDlg();     

    /**
    * Calls PrepareLC and RunLD with the supplied parameters
    */
    void PrepareAndRunLD(  );


private:

    /**
    * Exit function of CWiFiProtSelectNetworkDlg
    * @param aButtonId 
    * @return TBool exit or no
    */
    virtual TBool OkToExitL( TInt aButtonId );
    
    /**
    * PreLayoutDynInitL
    */
    void PreLayoutDynInitL();
    
    /**
    * Handles a change to the application's resources.
    * @param aType Type of resource change
    */
    void HandleResourceChange( TInt aType );
 
private:
    // Client's request status, dialog completes it when it finished
    TRequestStatus& iRequestStatus;
    // Selected item's index
    TInt& iSelected;
    // Icons array
    CArrayPtr<CGulIcon>* iIcons;
    // Items array
    CDesCArrayFlat* iItems;
    };

#endif  // C_WIFIPROTSELECTNETWORKDLG_H

// End of File
