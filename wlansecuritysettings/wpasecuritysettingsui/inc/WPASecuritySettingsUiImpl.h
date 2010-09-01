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
* Description: Declaration of class CWPASecuritySettingsUiImpl.  
*
*/

/*
* %version: tr1cfwln#8 %
*/

#ifndef WPASECURITYSETTINGSUIIMPL_H
#define WPASECURITYSETTINGSUIIMPL_H

// INCLUDES

#include <e32base.h>


// FORWARD DECLARATIONS

class CEikonEnv;
class CWPASecuritySettings;
class CWPASecuritySettingsUiImpl;
class CWPASecuritySettingsImpl;


// CLASS DECLARATION

/**
* WPA Security Settings UI implementation (behind proxy class
* CWPASecuritySettingsUi)
*/
NONSHARABLE_CLASS( CWPASecuritySettingsUiImpl ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aEikEnv Eikon environment.
        * @return The constructed CWPASecuritySettingsUiImpl object.
        */
        static CWPASecuritySettingsUiImpl* NewL( CEikonEnv& aEikEnv );

        /**
        * Destructor.
        */
        virtual ~CWPASecuritySettingsUiImpl();

    protected:  // Constructors

        /**
        * Constructor.
        * @param aEikEnv Eikon environment.
        */
        CWPASecuritySettingsUiImpl( CEikonEnv& aEikEnv );

        /**
        * Second-phase constructor.
        */
        void ConstructL();

    public:     // New methods

        /**
        * Edit the settings.
        * @param aSettings Settings to edit.
        * @param aTitle Title Pane text to display during edit.
        * @return Exit code. Value from CWPASecuritySettings::TEvent bits 
        * combined.
        */
        TInt EditL( CWPASecuritySettingsImpl& aSettings, const TDesC& aTitle );


    private:    // Data 

        // To hold the events
        TInt        iEventStore;

        // Resource file offset.
        TInt        iResOffset; 
        
        // Eikon environment. Not owned.
        CEikonEnv*  iEikEnv;        
    };

#endif 
