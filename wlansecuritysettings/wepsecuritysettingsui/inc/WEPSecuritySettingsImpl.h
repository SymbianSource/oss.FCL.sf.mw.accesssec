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
* Description: Declaration of class CWEPSecuritySettingsImpl.  
*
*/


#ifndef WEPSECURITYSETTINGSIMPL_H
#define WEPSECURITYSETTINGSIMPL_H

// INCLUDES
#include <e32base.h>

#include <WEPSecuritySettingsUI.h>
#include "WepSecuritySettingsDefs.h"

#include <metadatabase.h>
using namespace CommsDat;

// FORWARD DECLARATIONS

class CCommsDatabase;


// CLASS DECLARATION

/**
* WEP Security Settings.
* Implementation behind proxy class CWEPSecuritySettings.
*/
NONSHARABLE_CLASS( CWEPSecuritySettingsImpl ) : public CBase
    {

    public:     // Constructors and destructor

        /**
        * Two-phased constructor. Leaves on failure.
        * @return The constructed CWEPSecuritySettings object.
        */
        static CWEPSecuritySettingsImpl* NewL();

        /**
        * Destructor.
        */
        virtual ~CWEPSecuritySettingsImpl();

    protected:  // Constructors

        /**
        * Constructor.
        * @param aEikEnv Eikon environment.
        */
        CWEPSecuritySettingsImpl();

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
        * @param aIapId Wlan Service Table Id of the IAP to be saved
        * @param aCommsDb Comms database.
        */
        void SaveL( TUint32 aIapId, CCommsDatabase& aCommsDb ) const;

        /**
        * Tells if the settings are valid and can be saved
        * @return ETrue if all the compulsory settings have been entered
        */
        TBool IsValid();


        /**
        * Sets the new data of the key
        * @param aElement   Index of the element whose data has to be set.
        * @param aKeyData   The new value for data of the key.
        * @param aHex       ETrue if data is in Ascii format
        */
        TInt SetKeyDataL( const TInt aElement, const TDesC& aKeyData, 
                          const TBool aHex );


        /**
        * Calculates expected length of hex string of keyData on the base of
        * the selected key length.
        * @param aKeyLength Chosen key length
        * @return   Expected length
        */
        TInt ExpectedLengthOfKeyData( CWEPSecuritySettings::TWEPKeyLength 
                                                                  aKeyLength );


        /**
        * Gets Key currently in use
        * @return The key in use.
        */
        inline CWEPSecuritySettings::TWEPKeyInUse KeyInUse () const;

        /**
        * Sets Key currently in use
        * @param aKeyInUse  The new value for key in use.
        */
        inline void SetKeyInUse ( const CWEPSecuritySettings::TWEPKeyInUse 
                                                                   aKeyInUse );


        /**
        * Gets type of Authentication
        * @return The type of Authentication.
        */
        inline CWEPSecuritySettings::TWEPAuthentication Authentication () const;

        /**
        * Sets type of Authentication
        * @param aAuthentication    The new value for type of Authentication.
        */
        inline void SetAuthentication( 
              const CWEPSecuritySettings::TWEPAuthentication aAuthentication );


        /**
        * Gets the length of the key
        * @param aElement   Index of the element whose length has to be 
        *                   retrieved.
        * @return The length of the key
        */
        inline CWEPSecuritySettings::TWEPKeyLength KeyLength ( 
                                                   const TInt aElement ) const;

        /**
        * Sets the length of the key
        * @param aElement   Index of the element whose length has to be set.
        * @param aKeyLength The new value for length of the key.
        */
        inline void SetKeyLength( const TInt aElement, 
                        const CWEPSecuritySettings::TWEPKeyLength aKeyLength );


        /**
        * Gets the format of the key
        * @param aElement   Index of the element whose format has to be 
        *                   retrieved.
        * @return The format of the key
        */
        inline CWEPSecuritySettings::TWEPKeyFormat KeyFormat( 
                                                   const TInt aElement ) const;

        /**
        * Sets the format of the key
        * @param aElement   Index of the element whose format has to be set.
        * @param aKeyLength The new value for format of the key.
        */
        inline void SetKeyFormat( const TInt aElement, 
                        const CWEPSecuritySettings::TWEPKeyFormat aKeyFormat );


        /**
        * Gets the key data
        * @param aElement   Index of the element whose keyData has to be 
        *                   retrieved.
        * @return The data of the key
        */
        inline TDes8* KeyData( const TInt aElement );

        /**
        * Sets the new data of the key
        * @param aElement   Index of the element whose data has to be set.
        * @param aKeyLength The new value for data of the key.
        */
        inline void SetKeyData( const TInt aElement, const TDesC8& aKeyData );

        /**
        * Tells if the Wep256 feature is enabled or not
        * @return ETrue if the flag is enabled
        */
        inline TBool WEP256Enabled() const;

        /**
        * Verify if the entered keyData is valid
        * @param aTextToTest        The text to be verified
        * @param aLengthOfKeyData   The expected length of the keyData
        * @param aWEPKeyFormat      The format chosen to enter the keyData
        * @return   KErrNone if the text is valid, or error code if not.
        */
        TInt VerifyKeyData( const TDesC8& aTextToTest, TInt aLengthOfKeyData,
                            CWEPSecuritySettings::TWEPKeyFormat aWEPKeyFormat );

        /**
        * Converts keyData enetered in Ascii format to hex format
        * @param aSource    Source string
        * @param aDest      destination string
        */
        void ConvertAsciiToHex( const TDesC8& aSource, HBufC8*& aDest );
        
        /**
        * Load from database.
        * @param aIapId Wlan Service Table Id of the IAP to be loaded
        * @param aSession CommsDat session.
        */
        void LoadL( TUint32 aIapId, CMDBSession& aSession );
        
        /**
        * Save to database.
        * @param aIapId Wlan Service Table Id of the IAP to be saved
        * @param aSession CommsDat session.
        */
        void SaveL( TUint32 aIapId, CMDBSession& aSession ) const;


    private:

        /**
        * Sets keyLength parsing data contained in iKeyData
        * @param aIndex Index of the element whose length has to be calculated.
        */
        void SetLenKeyDataFromText( const TInt aIndex );


    private:    // Data 

        // Index of the key currently in use (EKeyNumber1, EKeyNumber2, 
        // EKeyNumber3, EKeyNumber4
        CWEPSecuritySettings::TWEPKeyInUse iKeyInUse;

        // Type of authentication (EAuthOpen, EAuthShared)
        CWEPSecuritySettings::TWEPAuthentication iAuthentication;

        // Length of the key (E40Bits, E104Bits, E232Bits)
        CWEPSecuritySettings::TWEPKeyLength iKeyLength[KMaxNumberofKeys];

        // Format of the key (EAscii, EHexadecimal)
        CWEPSecuritySettings::TWEPKeyFormat iKeyFormat[KMaxNumberofKeys];

        // Data of the key
        TBuf8<KMaxLengthOfKeyData> iKeyData[KMaxNumberofKeys];

        // Tells if the Wep256 feature is enabled
        TBool iIsWEP256Enabled;
    };

// Include inline functions
#include "WEPSecuritySettingsImpl.inl"


#endif 
