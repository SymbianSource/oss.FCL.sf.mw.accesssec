/*
* ============================================================================
*  Name     : wapisecuritysettingsuiimpl.h
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Declaration of class CWAPISecuritySettingsUiImpl.
*      
*  Version: %version:  3 %
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

#ifndef WAPISECURITYSETTINGSUIIMPL_H
#define WAPISECURITYSETTINGSUIIMPL_H

// INCLUDES

#include <e32base.h>


// FORWARD DECLARATIONS

class CEikonEnv;
class CWAPISecuritySettings;
class CWAPISecuritySettingsUiImpl;
class CWAPISecuritySettingsImpl;


// CLASS DECLARATION

/**
* WAPI Security Settings UI implementation (behind proxy class
* CWAPISecuritySettingsUi)
*/
NONSHARABLE_CLASS( CWAPISecuritySettingsUiImpl ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aEikEnv Eikon environment.
        * @return The constructed CWAPISecuritySettingsUiImpl object.
        */
        static CWAPISecuritySettingsUiImpl* NewL( CEikonEnv& aEikEnv );

        /**
        * Destructor.
        */
        virtual ~CWAPISecuritySettingsUiImpl();

    protected:  // Constructors

        /**
        * Constructor.
        * @param aEikEnv Eikon environment.
        */
        CWAPISecuritySettingsUiImpl( CEikonEnv& aEikEnv );

        /**
        * Second-phase constructor.
        */
        void ConstructL();

    public:     // New methods

        /**
        * Edit the settings.
        * @param aSettings Settings to edit.
        * @param aTitle Title Pane text to display during edit.
        * @return Exit code. Value from CWAPISecuritySettings::TEvent bits 
        * combined.
        */
        TInt EditL( CWAPISecuritySettingsImpl& aSettings, const TDesC& aTitle );


    private:    // Data 

        // To hold the events
        TInt        iEventStore;

        // Resource file offset.
        TInt        iResOffset; 
        
        // Eikon environment. Not owned.
        CEikonEnv*  iEikEnv;        
    };

#endif 
