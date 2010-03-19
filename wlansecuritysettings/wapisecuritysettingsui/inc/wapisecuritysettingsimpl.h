/*
* ============================================================================
*  Name     : wapisecuritysettingsimpl.h 
*  Part of  : WAPI Security Settings UI
*
*  Description:
*      Declaration of class CWAPISecuritySettingsImpl.
*      
*  Version: %version:  11.1.1 %
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

#ifndef WAPISECURITYSETTINGSIMPL_H
#define WAPISECURITYSETTINGSIMPL_H

// INCLUDES
#include <e32base.h>
#include <cmmanagerext.h>

#include <wapisecuritysettingsui.h>
#include "wapisecuritysettingsdefs.h"
#include <WapiCertificates.h>

#include <metadatabase.h>
#include <commsdattypesv1_1.h>

// FORWARD DECLARATIONS

// CLASS DECLARATION

/**
* WAPI Security Settings.
* Implementation behind proxy class CWAPISecuritySettings.
*/
NONSHARABLE_CLASS( CWAPISecuritySettingsImpl ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @return The constructed CWAPISecuritySettings object.
        */
        static CWAPISecuritySettingsImpl* NewL();

        
        /**
        * Destructor.
        */
        virtual ~CWAPISecuritySettingsImpl();

    protected:  // Constructors

        /**
        * Constructor.
        * @param aEikEnv Eikon environment.
        */
        CWAPISecuritySettingsImpl();

        
        /**
        * Second-phase constructor.
        */
        void ConstructL();

    public:     // New methods


        /**
        * Load from database.
        * @param aIapRecordId Iap record
        * @param aSession Commsdat session
        */
        void LoadL( TUint32 aIapRecordId, CommsDat::CMDBSession& aSession );
        
        
        /**
        * Save to database.
        * @param aIapRecordId Iap record
        * @param aSession Commsdat session
        */
        void SaveL( TUint32 aIapRecordId, CommsDat::CMDBSession& aSession ) const;
 
        
        /**
        * Resets certificate store from C drive
        */
        void ResetCertificateStoreL();
 
        /**
         * Load certificates. This was implemented for performance issues.
         */
        void LoadCertificatesL();
        
        
        /**
        * Delete AP related data from certificate database tables
        *
        * @param aId        Service table id
        */
        void DeleteAPSpecificDataL( const TInt aId );
        
        
        /**
         * Fetches table index by certificate label name
         * @param aCertificates     Pointer to certificate array
         * @param aCert             Certificate label
         * @return  Index to corresponding certificate label
         */
         TInt GetIndexByCertLabel( 
                             RArray<TBuf<KMaxLabelLength> >* aCertificates, 
                             const TDesC& aCert);
        

         /**
         * Read the value of the current user certificate label
         * @param aUserCertInUse  Fetched certificate label
         */
        inline void GetUserCertInUse( TInt& aUserCertInUse );

        
        /**
         * Read the value of the current CA certificate label
         * @param aCACertInUse  Fetched certificate label
         */
        inline void GetCACertInUse( TInt& aCACertInUse );
 
        
        /**
         * Sets the value of the current user certificate in use
         * @param aSelectedCert  The new value for user certificate
         */
        inline void SetUserCertInUse( const TInt aSelectedCert );

        
        /**
         * Sets the value of the current CA certificate in use
         * @param aSelectedCert  The new value for CA certificate
         */      
        inline void SetCACertInUse( const TInt aSelectedCert );
 
        
        /**
         * Fetches pointers to RARRAYS where user and CA certificates are
         * stored.
         * @param aUserCertificates Pointer reference to user certificates
         * @param aCACertificates Pointer reference to CA certificates
         */   
        inline void GetCertificateLabels ( 
                        RArray<TBuf<KMaxLabelLength> >*& aUserCertificates, 
                        RArray<TBuf<KMaxLabelLength> >*& aCACertificates );
        /**
         * Sets preshared key format, key, and wapi to PSK mode.
         */
        void SetPreSharedKeyL( const CWAPISecuritySettings::TWapiKeyFormat aKeyFormat, const TDesC& aPreSharedKey );

        /**
         * Read the value of the current authentication
         */
        TWapiAuth GetAuthentication( );
        
        /**
         * Sets the value of authentication  in use
         * @param aWapiAuth  Authentication
         */
        void SetAuthentication( TWapiAuth aWapiAuth );
        
        /**
         * Read the value of current key format
         */
        CWAPISecuritySettings::TWapiKeyFormat GetKeyFormat();
        
        /**
         * Sets the value of key format
         * @param aWapiKeyFormat Key format
         */
        void SetKeyFormat( CWAPISecuritySettings::TWapiKeyFormat aWapiKeyFormat ); 
        
        /**
         * Returns true if psk key is set
         */
        TBool hasWapiPSKKey();
        
        /**
         * Set the value of pre-shared wapi key
         * @param aWapiPSKKey Pre-shared key 
         */
        TInt SetWapiPSKKeyL( const TDesC& aWapiPSKKey );
        
        /**
         * Checks if current settings are valid.
         */
        TBool IsValid();
        
    private:
        /**
        * Checks whether the given string is a valid for current format
        * @param aPsk The string to be checked
        * @return ETrue if the string is a valid PSK, EFalse otherwise.
        */
        TBool IsValidPsk( const TDesC8& aPsk );

        /**
        * Checks whether the given string is a valid for given format
        * @param aWapiKeyFormat Format (ascii/hex)
        * @param aPsk The string to be checked
        * @return ETrue if the string is a valid PSK, EFalse otherwise.
        */
        TBool IsValidPsk( const CWAPISecuritySettings::TWapiKeyFormat aWapiKeyFormat,
                const TDesC8& aPsk );

    private:    // Data 

        CWapiCertificates*                  iCertificateStore; //owned

        // Certificate label, identity and selected certificate.
        RArray<TBuf<KMaxLabelLength> >*     iUserCertificates; //owned
        RArray<TBuf8<KMaxIdentityLength> >*  iUserCertificateData; //owned
        TInt                                iUserCertInUse; // Index of certificate data
        RArray<TBuf<KMaxLabelLength> >*     iCACertificates; //owned
        RArray<TBuf8<KMaxIdentityLength> >*  iCACertificateData; //owned
        TInt                                iCACertInUse; // Index of certificate data

        // Stores authentication method.
        TWapiAuth                           iWapiAuth;

        // True if PSK key is set
        TBool                               iWapiPSKKeySet;
        
        // PSK key format
        CWAPISecuritySettings::TWapiKeyFormat iWapiKeyFormat;
        
        // Stores PSK key.
        TBuf8<KWapiMaxKeyLength>            iWapiPSKKey;
        
        // Caches wlan service id to allow later loading of certificates
        // (solves performance issue)
        TUint32                             iWlanServiceId;

        // True if certificates have been loaded.
        TBool                               iCertificatesLoaded;
    };

// Include inline functions
#include "wapisecuritysettingsimpl.inl"

#endif 
