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
* Description: EAP Authentication Notifier
*
*/

/*
* %version: 19 %
*/

#ifndef __EAPAUTHNOTIFIER_H__
#define __EAPAUTHNOTIFIER_H__

// System includes
#include <e32base.h>
#include <hb/hbcore/hbdevicedialogsymbian.h>

// User includes

// Forward declarations

class TEapExpandedType; 
class CEapAuthObserver;

// External data types

//Global function prototypes

//Constants

const TUint KMaxNotifItemLength = 256;
const TUint KMaxUiDataLength = 1024;

/**
 * Callback interface
 */
class MNotificationCallback
    {
    public:
       /**
        * Notify for the client that the Dialog is complete
        *
        * @param  aStatus status
        * return  -
        */
        virtual void DlgComplete( TInt aStatus ) = 0;

       /**
        * Check if masterkey and password match
        *
        * @param  aPassword8 user entered password
        * return  true/false
        */

	    virtual TBool IsMasterKeyAndPasswordMatchingL(
	      const TDesC16 & aPassword) = 0;
	};

/**
 * EAP Notifier
 */
NONSHARABLE_CLASS ( CEapAuthNotifier ): public CBase
    {
    public:
        // Data types
        
        /** EAP Notifier types */
        enum EEapNotifierType
        {
            EEapNotifierTypeLEapUsernamePasswordDialog, 
            EEapNotifierTypeGTCQueryDialog,
            EEapNotifierTypePapAuthQueryDialog,
            EEapNotifierTypePapChallengeDialog, 
            EEapNotifierTypeGtcChallengeDialog, 
            EEapNotifierTypeFastInstallPacQueryDialog,
            EEapNotifierTypeFastPacStorePwQueryDialog,
            EEapNotifierTypeFastCreateMasterkeyQueryDialog, 
            EEapNotifierTypeFastPacFilePwQueryDialog, 
            EEapNotifierTypeFastStartAuthProvWaitNote, 
            EEapNotifierTypeFastStartUnauthProvWaitNote,
            EEapNotifierTypePapUsernamePasswordDialog,
            EEapNotifierTypeFastShowProvNotSuccessNote, 
            EEapNotifierTypeEapMsChapV2UsernamePasswordDialog,
            EEapNotifierTypeMsChapV2UsernamePasswordDialog, 
            EEapNotifierTypeMsChapV2NewPasswordDialog, 
            EEapNotifierTypeMsChapV2OldPasswordDialog,
            EEapNotifierTypeMsChapV2PasswordExpiredNote,
            EEapNotifierTypeGTCUsernamePasswordDialog,
        }; 
        
        /**  EAP Notifier Data struct */
        struct TEapDialogInfo
        {
            TBool iPasswordPromptEnabled;
            TBool iIsIdentityQuery;
            TBuf16<KMaxNotifItemLength> iUsername;
            TBuf16<KMaxNotifItemLength> iPassword;
            TBuf16<KMaxNotifItemLength> iOldPassword; 
            TBool iIsFirstQuery;
            TBuf16<KMaxUiDataLength> iUidata;
        };
                     
        /**
        * Two-phased constructor.
        */
        IMPORT_C  static CEapAuthNotifier* NewL( MNotificationCallback& aClient );
        
        /**
        * Destructor
        */
        ~CEapAuthNotifier();
    
    public:          
        /**
        * Start the Notifier
        *
        * @param  aType            notifier type
        * @param  aPasswordInfo    data to be filled
        * @param  aEapType         eap type
        * return -
        */
        IMPORT_C void StartL( EEapNotifierType aType,
                              TEapDialogInfo* aEapInfo,
                              TEapExpandedType& aEapType );
        
        /**
        * Cancel() the notifier
        *
        * @param  -
        * return -
        */
        IMPORT_C void Cancel();
                 
        /**
        * CompleteL the notifier is complete
        *
        * @param  aStatus status
        * return  -
        */
        void CompleteL( TInt aStatus );
        
        /**
        * Sets the selected user name and password of the presented dialog
        *
        * @param  aPasswordInfo password 
        * return  -
        */
        void SetSelectedUnameAndPwd( TEapDialogInfo& aPasswordInfo );
                
        /**
        * Sets the selected password of the presented dialog
        *
        * @param  aPasswordInfo password 
        * return  -
        */
        void SetSelectedPassword(
                TEapDialogInfo& aPasswordInfo );
        
        /**
        * Sets the selected Old password of the presented dialog
        *
        * @param  aPasswordInfo old password 
        * return  -
        */
        void SetSelectedOldPassword(
                TEapDialogInfo& aPasswordInfo );
                
        /**
        * Checks the selected password of the presented dialog
        *
        * @param  aPasswordInfo password 
        * return  TRUE or FALSE
        */       
        TBool CheckPasswordMatchingL( TEapDialogInfo& aPasswordInfo );  
        
        /**
        * Updates the parameters of the presented dialog
        *
        * @param  aIsPwdCorrect indicates if pwd data was correct
        * return  -
        */       
        void UpdateDialogL( TBool aIsPwdCorrect ); 
       
    private:
        /**
        * Constructor
        */
        CEapAuthNotifier( MNotificationCallback& aClient );
        
        /**
        * ConstructL
        */
        void ConstructL();
        
        /**
        * Set data for the UsernamePassword Dialog(s)
        *
        * @param  aPasswordInfo    data to be filled
        * @param  aEapType         Eap type to be used
        * @param  aMap             Pointer to variant data
        * @param  aAuthMethod      Authentication method to be used
        * return -
        */
        void SetUsernamePasswordDataL( 
            TEapDialogInfo* aPasswordInfo,
            TEapExpandedType& aEapType,
            CHbSymbianVariantMap* aMap,
            const TDesC& aAuthMethod );
                
        
        /**
        * Set data for the query Dialog(s)
        *
        * @param  aEapInfo         data to be filled
        * @param  aMap             Pointer to variant data
        * @param  aAuthMethod      Authentication method to be used
        * return -
        */
        void SetQueryDialogDataL( 
            TEapDialogInfo* aEapInfo,
            CHbSymbianVariantMap* aMap,
            const TDesC& aAuthMethod );
        
       /**
        * Set data for the Install Pac query Dialog(s)
        *
        * @param  aEapInfo         data to be filled
        * @param  aMap             Pointer to variant data
        * return -
        */
        void SetFastInstallPacQueryDialogDataL( 
            TEapDialogInfo* aEapInfo,
            CHbSymbianVariantMap* aMap );
        
       /**
        * Set data for the Pac file query Dialog(s)
        *
        * @param  aEapInfo         data to be filled
        * @param  aMap             Pointer to variant data
        * return -
        */
        void SetFastPacFileQueryPwDialogDataL( 
            TEapDialogInfo* aEapInfo,
            CHbSymbianVariantMap* aMap );
        
       /**
        * Set data for the prov wait note Dialog(s)
        *
        * @param  aMap                  Pointer to variant data
        * @param  aAuthProvWaitNote     Tells whether auth or unauth 
        * return -
        */
        void SetFastProvWaitNoteDialogDataL( 
            CHbSymbianVariantMap* aMap,
            TBool aAuthProvWaitNote );
                    
       /**
        * Set data for the Password Dialog(s)
        *
        * @param  aEapType         Eap type to be used
        * @param  aMap             Pointer to variant data
        * @param  aAuthMethod      Authentication method to be used
        * return -
        */
        void SetPasswordQueryDataL( 
            TEapExpandedType& aEapType,
            CHbSymbianVariantMap* aMap,
            const TDesC& aAuthMethod );
            
                
    private: // Data
        
        /** 
         * For callback 
         */
        MNotificationCallback& iClient;  
        
        /** 
         * Pointer to the device dialog interface for handling the dialog 
         */
        CHbDeviceDialogSymbian* iDialog;
        
        /** 
         * The observer to handle the data received from the orbit dialog 
         */
        CEapAuthObserver* iObserver;
                        
        /** 
         * Information if request was already completed, in case the
         * observer receives the data signal and the signal about closing the
         * dialog.
         */
        TBool iCompleted;
        
        /**
         * Information if request was already cancelled.
         */
        TBool iCancelled;
        
        /** 
         * Pointer to the Eap Dialog Info structure 
         */
        TEapDialogInfo* iEapInfo;
        
    
    };

#endif //__EAPAUTHNOTIFIER_H__

