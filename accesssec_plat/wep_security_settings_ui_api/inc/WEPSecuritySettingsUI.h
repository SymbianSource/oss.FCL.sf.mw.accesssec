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
* Description: Declares the main handler CWEPSecuritySettings, UI CWEPSecuritySettingsUI and public API for the WEP Security Settings. 
*
*/


#ifndef WEPSECURITYSETTINGSUI_H
#define WEPSECURITYSETTINGSUI_H

// INCLUDES

#include <e32base.h>

#include <metadatabase.h>
using namespace CommsDat;

// FORWARD DECLARATIONS
class CEikonEnv;
class CWEPSecuritySettingsUi;
class CWEPSecuritySettingsUiImpl;
class CWEPSecuritySettingsImpl;
class CCommsDatabase;



// CLASS DECLARATION
/*
* WEP Security Settings. Enables loading, saving and editing the settings
* (editing via CWEPSecuritySettingsUi).
* Proxy around the real implementation in CWEPSecuritySettingsUiImpl. 
* No details of the actual data are exposed.
*/
NONSHARABLE_CLASS( CWEPSecuritySettings ) : public CBase
    {

    public: // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @return The constructed CWEPSecuritySettings object.
        */
        IMPORT_C static CWEPSecuritySettings* NewL();


        /**
        * Destructor.
        */
        IMPORT_C ~CWEPSecuritySettings();


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


        // Members to be showed in the setting pages
        enum TWepMember
            {
            EWepKeyInUse,           // To set key in use
            EWepAuthentication,     // To set authentication type
            EWepKeyConfiguration,   // To open the other settings (the three below)

            EWepKeyLength,          // To set the length of the key
            EWepKeyFormat,          // To choose the format of the key
            EWepKeyData             // To set the key
            };


        // Enumeration of the possible keys in use
        enum TWEPKeyInUse
            {
            EKeyNumber1,            // Key number 1
            EKeyNumber2,            // Key number 2
            EKeyNumber3,            // Key number 3
            EKeyNumber4             // Key number 4
            };


        // Enumeration of the possible authentication types
        enum TWEPAuthentication
            {
            EAuthOpen,              // Open authentication
            EAuthShared             // Shared authentication
            };


        // Possible lengths of the keys
        enum TWEPKeyLength
            {
            E40Bits,                // 40 bits
            E104Bits,               // 104 bits
            E232Bits                // 232 bits
            };


        // Possible formats of the keys
        enum TWEPKeyFormat
            {
            EAscii,                 // Ascii format
            EHexadecimal            // Hex format
            };
    
    public:     // New methods

        /**
        * Load from database.
        * @param aIapId Wlan Service Table Id of the IAP to be loaded
        * @param aCommsDb Comms database.
        */
        IMPORT_C void LoadL( TUint32 aIapId, CCommsDatabase& aCommsDb );
        
        /**
        * Edit the settings.
        * @param aUi UI to be used.
        * @param aTitle Title Pane text to display during edit.
        * @return Exit reason.
        */
        IMPORT_C TInt EditL( CWEPSecuritySettingsUi& aUi, 
                             const TDesC& aTitle );

        /**
        * Save to database.
        * @param aIapId Wlan Service Table Id of the IAP to be saved
        * @param aCommsDb Comms database.
        */
        IMPORT_C void SaveL( TUint32 aIapId, CCommsDatabase& aCommsDb ) const;
        
        /**
        * Tells if the settings are valid and can be saved
        * @return ETrue if all the compulsory settings have been entered
        */
        IMPORT_C TBool IsValid() const;

        /**
        * Sets the new data of the key
        * @param aElement   Index of the element whose data has to be set.
        * @param aKeyData   The new value for data of the key.
        * @param aHex       ETrue if data is in Ascii format
        * @return KErrNone if successful, or an error code
        */
        IMPORT_C TInt SetKeyDataL( const TInt aElement, const TDesC& aKeyData,
                                   const TBool aHex );
        
        /**
        * Load from database.
        * @param aIapId Wlan Service Table Id of the IAP to be loaded
        * @param aSession Session to CommsDat.
        */
        IMPORT_C void LoadL( TUint32 aIapId, CMDBSession& aSession );
        
        /**
        * Save to database.
        * @param aIapId Wlan Service Table Id of the IAP to be saved
        * @param aSession Session to CommsDat.
        */
        IMPORT_C void SaveL( TUint32 aIapId, CMDBSession& aSession ) const;

        /**
        * Sets the index of the key to use.
        * @param aKey   The key to be used for authentication.
        */
        IMPORT_C void SetKeyInUse( TWEPKeyInUse aKey );
        
        /**
        * Sets the authentication type.
        * @param aAuthentication   The authentication type.
        */
        IMPORT_C void SetAuthentication( TWEPAuthentication aAuthentication );
        

    private:    // Data 

        // Implementation. Owned.
        CWEPSecuritySettingsImpl* iImpl;  

    };



/**
* User interface to edit WEP Security Settings.
* Proxy around the real implementation in CWEPSecuritySettingsUiImpl.
*/
NONSHARABLE_CLASS( CWEPSecuritySettingsUi ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aEikEnv Eikon environment.
        * @return The constructed CWEPSecuritySettingsUi object.
        */
        IMPORT_C static CWEPSecuritySettingsUi* NewL( CEikonEnv& aEikEnv );

        /**
        * Destructor.
        */
        IMPORT_C virtual ~CWEPSecuritySettingsUi();

    public:     // New methods

        /**
        * Component Validation Test.
        * @return KErrNone.
        */
        IMPORT_C static TInt Cvt();

    private:    // Friends

        friend class CWEPSecuritySettings;

    private:    // Data 

        // Implementation. Owned.
        CWEPSecuritySettingsUiImpl* iImpl;

    };
#endif


// End of File
