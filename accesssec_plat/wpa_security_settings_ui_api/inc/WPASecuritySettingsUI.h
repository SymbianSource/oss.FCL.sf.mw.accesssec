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
* Description: Declares the main handler CWPASecuritySettings, UI CWPASecuritySettingsUI and public API for the WPA Security Settings. 
*
*/

/*
* %version: 5 %
*/

#ifndef WPASECURITYSETTINGSUI_H
#define WPASECURITYSETTINGSUI_H

// INCLUDES

#include <e32base.h>

#include <metadatabase.h>
using namespace CommsDat;

// FORWARD DECLARATIONS
class CEikonEnv;
class CWPASecuritySettingsUi;
class CWPASecuritySettingsUiImpl;
class CWPASecuritySettingsImpl;
class CCommsDatabase;


// ENUMERATIONS

// Security mode in use
enum TSecurityMode
    {
    ESecurityMode8021x = 4,     // 802.1x
    ESecurityModeWpa = 8        // WPA
    };


// Type of saving
enum TTypeOfSaving
    {
    ESavingEditedAP,      // Save an already existing AP that was edited.
    ESavingBrandNewAP,    // Save a just created AP started from default values
    ESavingNewAPAsACopy   // Save a new AP as a copy of an already existing AP
    };




// CLASS DECLARATION
/*
* WPA Security Settings. Enables loading, saving and editing the settings
* (editing via CWPASecuritySettingsUi).
* Proxy around the real implementation in CWPASecuritySettingsUiImpl. 
* No details of the actual data are exposed.
*/
NONSHARABLE_CLASS( CWPASecuritySettings ) : public CBase
    {

    public: // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aSecurityMode  The chosen security mode. It can be 
        *                       ESecurityMode8021x or ESecurityModeWpa
        * @return The constructed CWPASecuritySettings object.
        */
        IMPORT_C static CWPASecuritySettings* NewL( 
                                                TSecurityMode aSecurityMode );


        /**
        * Destructor.
        */
        IMPORT_C ~CWPASecuritySettings();


    public:     // Types

        enum TEvent                     // Events happening during edit.
            {
            ENone           = 0x0000,   // Nothing happened.
            EModified       = 0x0001,   // Data changed.
            EValid          = 0x0010,   // All data entererd are valid, they
                                        // can be saved
            EExitReq        = 0x0020,   // Exit option requested, also caller 
                                        // app should close
            EShutDownReq    = 0x0040    // ShutDown was requested
            };


    public:     // New methods

        /**
        * Load from database.
        * @param Wlan Service Table Id of the IAP to be loaded
        * @param aCommsDb Comms database.
        */
        IMPORT_C void LoadL( TUint32 aIapId, CCommsDatabase& aCommsDb );
        

        /**
        * Edit the settings.
        * @param aUi UI to be used.
        * @param aTitle Title Pane text to display during edit.
        * @return Exit reason.
        */
        IMPORT_C TInt EditL( CWPASecuritySettingsUi& aUi, 
                             const TDesC& aTitle );

        /**
        * Save to database.
        * @param aIapId     Wlan Service Table Id of the IAP to be saved
        * @param aCommsDb   Comms database.
        * @param aTypeOfSaving	Tells what kind of AP we are going to save: it 
        *                       can be ESavingEditedAP, ESavingBrandNewAP, or 
        *                       ESavingNewAPAsACopy
        * @param aOldIapId  The old Id of the IAP; it is used to save the EAP 
        *                   configuration, only when aIsNewAP is ETrue
        */
        IMPORT_C void SaveL( TUint32 aIapId, 
                             CCommsDatabase& aCommsDb, 
                             TTypeOfSaving aTypeOfSaving, 
                             TUint32 aOldIapId ) const;


        /**
        * Delete from database. It actually just removes EAP Configuration.
        * @param aIapId Id of the IAP to be saved
        */
        IMPORT_C void DeleteL( TUint32 aIapId ) const;


        /**
        * Tells if the settings are valid and can be saved
        * @return ETrue if all the compulsory settings have been entered
        */
        IMPORT_C TBool IsValid() const;


        /**
        * Sets the Pre-shared key
        * @param aPreSharedKey  The key to be set
        * @return KErrNone if successful, or an error code
        */
        IMPORT_C TInt SetWPAPreSharedKey( const TDesC& aPreSharedKey );
        
        
        /**
        * Load from database.
        * @param aIapId Wlan Service Table Id of the IAP to be loaded
        * @param aSession CommsDat session.
        */
        IMPORT_C void LoadL( TUint32 aIapId, CMDBSession& aSession );
        
        
        /**
        * Save to database.
        * @param aIapId     Wlan Service Table Id of the IAP to be saved
        * @param aSession   CommsDat session.
        * @param aTypeOfSaving	Tells what kind of AP we are going to save: it 
        *                       can be ESavingEditedAP, ESavingBrandNewAP, or 
        *                       ESavingNewAPAsACopy
        * @param aOldIapId  The old Id of the IAP; it is used to save the EAP 
        *                   configuration, only when aIsNewAP is ETrue
        */
        IMPORT_C void SaveL( TUint32 aIapId, 
                             CMDBSession& aSession, 
                             TTypeOfSaving aTypeOfSaving, 
                             TUint32 aOldIapId ) const;

        /**
        * Sets the list of enabled EAP types.
        * @param aEnabledPluginList Enumeration of enabled plugins 
        *                           in expanded EAP type format
        * @return KErrNone if successful, or an error code
        */
        IMPORT_C TInt SetWPAEnabledEAPPlugin( const TDesC8& aEnabledPluginList );


        /**
        * Sets the list of disabled EAP types
        * @param aDisabledPluginList Enumeration of disabled plugins
        *                            in expanded EAP type format
        * @return KErrNone if successful, or an error code
        */
        IMPORT_C TInt SetWPADisabledEAPPlugin( const TDesC8& aDisabledPluginList );
        

    private:    // Data 

        // Implementation. Owned.
        CWPASecuritySettingsImpl* iImpl;  

    };



/**
* User interface to edit WPA Security Settings.
* Proxy around the real implementation in CWPASecuritySettingsUiImpl.
*/
NONSHARABLE_CLASS( CWPASecuritySettingsUi ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aEikEnv Eikon environment.
        * @return The constructed CWPASecuritySettingsUi object.
        */
        IMPORT_C static CWPASecuritySettingsUi* NewL( CEikonEnv& aEikEnv );

        /**
        * Destructor.
        */
        IMPORT_C virtual ~CWPASecuritySettingsUi();

    public:     // New methods

        /**
        * Component Validation Test.
        * @return KErrNone.
        */
        IMPORT_C static TInt Cvt();

    private:    // Friends

        friend class CWPASecuritySettings;

    private:    // Data 

        // Implementation. Owned.
        CWPASecuritySettingsUiImpl* iImpl;

    };
#endif


// End of File
