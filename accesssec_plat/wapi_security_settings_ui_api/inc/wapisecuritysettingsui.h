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
* Description: Declares the main handler CWAPISecuritySettings, UI CWAPISecuritySettingsUI and public API for the WAPI Security Settings. 
*
*/

/*
* %version: 10 %
*/

#ifndef WAPISECURITYSETTINGSUI_H
#define WAPISECURITYSETTINGSUI_H

// INCLUDES

#include <e32base.h>
#include <WapiCertificates.h>

#include <metadatabase.h>
#include <commsdattypesv1_1.h>

using namespace CommsDat;

// FORWARD DECLARATIONS
class CEikonEnv;
class CWAPISecuritySettingsUi;
class CWAPISecuritySettingsUiImpl;
class CWAPISecuritySettingsImpl;
class CCommsDatabase;

// CLASS DECLARATION
/*
* WAPI Security Settings. Enables loading, saving and editing the settings
* (editing via CWAPISecuritySettingsUi).
* Proxy around the real implementation in CWAPISecuritySettingsUiImpl. 
*/
NONSHARABLE_CLASS( CWAPISecuritySettings ) : public CBase
    {

    public: // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @return The constructed CWAPISecuritySettings object.
        */
        IMPORT_C static CWAPISecuritySettings* NewL();


        /**
        * Destructor.
        */
        IMPORT_C ~CWAPISecuritySettings();


    public:     // Types

        enum TEvent                     // Events happening during edit.
            {
            ENone           = 0x0000,   // Nothing happened.
            EModified       = 0x0001,   // Data changed.
            EValid          = 0x0010,   // All data entered are valid, they can be
                                        // saved
            
            EExitReq        = 0x0020,   // Exit option requested, also caller 
                                        // app should close
            EShutDownReq    = 0x0040    // ShutDown was requested
            };
        
        enum TWapiKeyFormat
            {
            EWapiKeyAscii   = 0,
            EWapiKeyHex     = 1
            };
        
    public:     // New methods

        
        /**
        * Edit WAPI certificate settings.
        * @param aUi UI to be used.
        * @param aTitle Title Pane text to display during edit.
        * @return Exit reason.
        */
        IMPORT_C TInt EditL( CWAPISecuritySettingsUi& aUi, 
                             const TDesC& aTitle );

        
        /**
        * Load WAPI certificate settings and configuration from database.
        * @param aIapRecordID 
        * @param aSession Commsdat session
        */
        IMPORT_C void LoadL( TUint32 aIapRecordId, CMDBSession& aSession );

        /**
        * Tells if the settings are valid and can be saved
        * @return ETrue if all the compulsory settings have been entered
        */
        IMPORT_C TBool IsValid() const;

        /**
        * Save WAPI certificate settings of the IAP to the database.
        * @param aIapRecordID 
        * @param aSession Commsdat session
        */
        IMPORT_C void SaveL( TUint32 aIapRecordId, CMDBSession& aSession ) const;

        /**
        * Sets the Pre-shared key. Also sets Authentication method to PSK.
        * @param aKeyFormat     Key format
        * @param aPreSharedKey  The key to be set
        */
        IMPORT_C void SetPreSharedKeyL( const TWapiKeyFormat aKeyFormat, const TDesC& aPreSharedKey );
                
        /**
        * Delete AP related data from certificate database tables
        *
        * @param aId        Service table id
        */
        IMPORT_C void DeleteAPSpecificDataL( const TInt aId );
    
    private:    // Data 

        // Implementation. Owned.
        CWAPISecuritySettingsImpl* iImpl;  

    };

/**
* User interface to edit WAPI Security Settings.
* Proxy around the real implementation in CWAPISecuritySettingsUiImpl.
*/
NONSHARABLE_CLASS( CWAPISecuritySettingsUi ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aEikEnv Eikon environment.
        * @return The constructed CWAPISecuritySettingsUi object.
        */
        IMPORT_C static CWAPISecuritySettingsUi* NewL( CEikonEnv& aEikEnv );

        /**
        * Destructor.
        */
        IMPORT_C virtual ~CWAPISecuritySettingsUi();

    private:    // Friends

        friend class CWAPISecuritySettings;

    private:    // Data 

        // Implementation. Owned.
        CWAPISecuritySettingsUiImpl* iImpl;

    };
#endif


// End of File
