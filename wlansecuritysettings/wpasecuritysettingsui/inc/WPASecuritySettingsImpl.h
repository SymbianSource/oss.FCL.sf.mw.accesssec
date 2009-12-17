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
* Description: Declaration of class CWPASecuritySettingsImpl.  
*
*/


#ifndef WPASECURITYSETTINGSIMPL_H
#define WPASECURITYSETTINGSIMPL_H

// INCLUDES
#include <e32base.h>
#include <WlanCdbCols.h>

#include <WPASecuritySettingsUI.h>

#include <metadatabase.h>
using namespace CommsDat;



// CONST DECLARATIONS
#define KWLANEAPLISTLENGTH 1024     // Max length of the EAP Plugin list


// FORWARD DECLARATIONS
class CCommsDatabase;
class CEAPPluginConfigurationIf;

// CLASS DECLARATION

/**
* WPA Security Settings.
* Implementation behind proxy class CWPASecuritySettings.
*/
NONSHARABLE_CLASS( CWPASecuritySettingsImpl ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @param aSecurityMode  The chosen security mode. It can be 
        *                       ESecurityMode8021x or ESecurityModeWpa
        * @return The constructed CWPASecuritySettings object.
        */
        static CWPASecuritySettingsImpl* NewL( TSecurityMode aSecurityMode );

        /**
        * Destructor.
        */
        virtual ~CWPASecuritySettingsImpl();


    protected:  // Constructors

        /**
        * Constructor.
        * @param aSecurityMode  The chosen security mode. It can be 
        *                       ESecurityMode8021x or ESecurityModeWpa
        */
        CWPASecuritySettingsImpl( TSecurityMode aSecurityMode );

        /**
        * Second-phase constructor.
        */
        void ConstructL();


    public:     // New methods

        /**
        * Load from database.
        * @param aIapId Wlan Service Table Id of the IAP to be loaded
        * @param aCommsDb Comms database.
        */
        void LoadL( TUint32 aIapId, CCommsDatabase& aCommsDb );
        

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
        void SaveL( TUint32 aIapId, CCommsDatabase& aCommsDb, 
                    TTypeOfSaving aTypeOfSaving, TUint32 aOldIapId );


        /**
        * Delete from database. It actually just removes EAP Configuration.
        * @param aIapId Id of the IAP to be saved
        */
        void DeleteL( TUint32 aIapId );


        /**
        * Tells if the settings are valid and can be saved
        * @return ETrue if all the compulsory settings have been entered
        */
        TBool IsValid();


        /**
        * Sets the Pre-shared key
        * @param aPreSharedKey  The key to be set
        * @return KErrNone if successful, or an error code
        */
        TInt SetWPAPreSharedKey( const TDesC& aPreSharedKey );

        /**
        * Gets the type of Security set.
        * @return The security mode in use. It can be ESecurityMode8021x or
        *         ESecurityModeWpa
        */
        inline TSecurityMode SecurityMode() const;

        
        /**
        * Tells if Pre-shared key is in use or not
        * @return   ETrue if Pre-shared key is in use
        */
        inline TBool WPAMode() const;

        
        /**
        * Sets the use of Pre-shared key.
        * @param aWPAMode   ETrue if pre-shared key is in use
        */
        inline void SetWPAMode( const TBool aWPAMode );


        /**
        * Tells if it is WPA2 Only mode
        * @return ETrue if it is WPA2 Only mode
        */
        inline TBool Wpa2Only() const;


        /**
        * Sets the WPA2 Only mode enabling variable
        * @param aAllowed   ETrue if WPA2 Only mode is enabled
        */
        inline void SetWpa2Only( const TBool aAllowed );


        /**
        * Returns the Pre-shared key
        * @return The pre-shared key
        */
        inline TDes8* WPAPreSharedKey();


        /**
        * Sets the Pre-shared key
        * @param aPreSharedKey  The key to be set
        */
        inline void SetWPAPreSharedKey( const TDesC8& aPreSharedKey );


        /**
        * Returns the content of the WlanEapList column of WLANServiceTable
        * @return The content string
        */
        inline TDes* WPAEAPPlugin();

        /**
        * Returns the content of the WlanEnabledEapList column of 
        * WLANServiceTable
        * @return The content string. Ownership not passed!
        */
        inline HBufC8* WPAEnabledEAPPlugin();
        
        /**
        * Returns the content of the WlanDisabledEapList column of 
        * WLANServiceTable
        * @return The content string. Ownership not passed!
        */
        inline HBufC8* WPADisabledEAPPlugin();

        /**
        * Sets the content of the WlanEapList column of WLANServiceTable
        * @param aPluginList The content string to be set
        */
        inline void SetWPAEAPPlugin( const TDes& aPluginList );

        /**
        * Sets the content of the WlanEnabledEapList column of WLANServiceTable 
        * (for expanded EAP types)
        * @param aEnabledPluginList Enumeration of enabled plugins
        * @return KErrNone if successful, or an error code
        */
        TInt SetWPAEnabledEAPPlugin( const TDesC8& aEnabledPluginList );

        /**
        * Sets the content of the WlanDisabledEapList column of WLANServiceTable 
        * (for expanded EAP types)
        * @param aDisabledPluginList Enumeration of disabled plugins
        * @return KErrNone if successful, or an error code
        */
        TInt SetWPADisabledEAPPlugin( const TDesC8& aDisabledPluginList );

        /**
        * Sets the Id of the AP 
        * @param aIapId  The Id to be set
        */
        inline void SetIapId( const TUint32 aIapId );
        
        /**
        * Returns the Id of the AP 
        * @return The Id
        */
        inline const TUint32 IapId();

        /**
        * Returns the pointer to the EAP Configuration plugin
        * @return The EAP Configuration plugin
        */
        inline CEAPPluginConfigurationIf* Plugin();
        
        /**
        * Load from database.
        * @param aIapId Wlan Service Table Id of the IAP to be loaded
        * @param aSession CommsDat session.
        */
        void LoadL( TUint32 aIapId, CMDBSession& aSession );
        
        
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
        void SaveL( TUint32 aIapId, CMDBSession& aSession, 
                    TTypeOfSaving aTypeOfSaving, TUint32 aOldIapId );

    private:
        /**
        * Checks whether the given string is a valid PSK
        * @since S60 5.0
        * @param aPsk The string to be checked
        * @return ETrue if the string is a valid PSK, EFalse otherwise.
        */
        TBool IsValidPsk( const TDesC8& aPsk );

    private:    // Data 

        // Security mode in use
        TSecurityMode iSecurityMode;

        // Pre-shared key in use or not
        TBool iWPAMode;

        // The content of the WlanEapList column of WLANServiceTable
        TBuf<KWLANEAPLISTLENGTH> iWPAEAPPlugin;

        // The pre-shared key
        TBuf8<KWlanWpaPskLength> iWPAPreSharedKey;

        // The content of the WlanEnabledEapList column of WLANServiceTable.
        // Owned.
        HBufC8 *iWPAEnabledEAPPlugin;
        
        // The content of the WlanDisabledEapList column of WLANServiceTable.
        // Owned.
        HBufC8 *iWPADisabledEAPPlugin;        

        // WPA2 Only mode enabled or not
        TBool iWpa2Only;
        
        // The Id of the AP.
        TUint32 iIapId;

        // The EAP Configuration plugin. Owned.
        CEAPPluginConfigurationIf* iPlugin;
    };

// Include inline functions
#include "WPASecuritySettingsImpl.inl"


#endif 
