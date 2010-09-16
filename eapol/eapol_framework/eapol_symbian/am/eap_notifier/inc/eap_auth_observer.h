/*
* Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies). 
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description: Dialog Observer implementation
*
*/

/*
* %version: 12 %
*/

#ifndef __EAPAUTHOBSERVER_H__
#define __EAPAUTHOBSERVER_H__

// System includes

// User includes

// Forward declarations
class CEapAuthNotifier;

// External data types

//Global function prototypes

//Constants

/**
 * EAP Observer
 */
NONSHARABLE_CLASS ( CEapAuthObserver ) : public CBase, public MHbDeviceDialogObserver
    {
    public:
        /**
        * Two-phased constructor.
        */
        static CEapAuthObserver* NewL( 
                CEapAuthNotifier* aNotifier
                );
                
        /**
        * Destructor
        */
        ~CEapAuthObserver();
        
        /**
        * Handles the setting of the notifier (dialog) type
        *
        * @param    aType EEapNotifierType
        * return -
        */
        void SetNotifierType( CEapAuthNotifier::EEapNotifierType aType );
            
        /**
        * Handles the user input received from the dialog
        *
        * @param    aData CHbSymbianVariantMap&
        * return -
        */
        void DataReceived( CHbSymbianVariantMap& aData );
        
        /**
        * Handles the closing of the dialog
        *
        * @param    aCompletionCode TInt
        * return -
        */
        void DeviceDialogClosed( TInt aCompletionCode );
    private:
        /**
        * Constructor
        */
        CEapAuthObserver( CEapAuthNotifier* aNotifier );
        
        /**
        * Handles the user name password input received from the dialog
        *
        * @param    aData CHbSymbianVariantMap&
        * return -
        */
        void UsernamePasswordDlgDataReceived( CHbSymbianVariantMap& aData );
          
        /**
        * Handles the password query user input received from the dialog
        *
        * @param    aData CHbSymbianVariantMap&
        * return -
        */
        void PwdQueryDataReceived( CHbSymbianVariantMap& aData );
        
        /**
        * Handles the old password query user input received from the dialog
        *
        * @param    aData CHbSymbianVariantMap&
        * return -
        */
        void OldPwdQueryDataReceived( CHbSymbianVariantMap& aData );

        /**
        * Handles the Pac Store password query user input received from the dialog
        *
        * @param    aData CHbSymbianVariantMap&
        * return -
        */            
        void PacStorePwdQueryDataReceived( CHbSymbianVariantMap& aData );
        
    private: // Data
        /** 
         * Pointer to the object that triggered the dialog opening,
         * needed to update the information about the user input.
         */
        CEapAuthNotifier* iNotifier;
        
        /** 
         * Current EAP notifier type to serve 
         */
        CEapAuthNotifier::EEapNotifierType iType;
    };

#endif /* __EAPAUTHOBSERVER_H__ */
