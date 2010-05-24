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
* Description: Eap Dialog implementation
*
*/

#ifndef __EAPAUTHNOTIFIER_H__
#define __EAPAUTHNOTIFIER_H__

#include <e32base.h>
#include <hb/hbcore/hbdevicedialogsymbian.h>

const TUint KMaxNotifItemLength = 256;
const TUint KMaxUiDataLength = 1024;

/**
 * Callback interface
 */
class MNotificationCallback
    {
    public:
        virtual void DlgComplete( TInt aStatus ) = 0;
    };

class TEapExpandedType;
class CEapAuthObserver;


NONSHARABLE_CLASS ( CEapAuthNotifier ): public CBase
    {
    public:
        
        enum EEapNotifierType
        {
            EEapNotifierTypeLEapUsernamePasswordDialog, 
            EEapNotifierTypeGTCSecurIDPasscodeQueryUidDialog,
            EEapNotifierTypeGTCQueryDialog,
            EEapNotifierTypePapAuthQueryDialog,
            EEapNotifierTypePapChallengeReplyQueryDialog, 
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
        
        /**
        * Start the Notifier
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
        * @param  -
        * return -
        */
        IMPORT_C void Cancel();
        
    public:           
        /**
        * CompleteL the notifier is complete
        * @param  aStatus status
        * return  -
        */
        void CompleteL( TInt aStatus );
        
        /**
        * Sets the selected user name and password of the presented dialog
        * @param  aPasswordInfo password 
        * return  -
        */
        void SetSelectedUnameAndPwd( TEapDialogInfo& aPasswordInfo );
                
        /**
        * Sets the selected password of the presented dialog
        * @param  aPasswordInfo password 
        * return  -
        */
        void SetSelectedPassword(
                TEapDialogInfo& aPasswordInfo );
        
        /**
        * Sets the selected Old password of the presented dialog
        * @param  aPasswordInfo old password 
        * return  -
        */
        void SetSelectedOldPassword(
                TEapDialogInfo& aPasswordInfo );
       
    private:
        /**
        * Constructor
        */
        CEapAuthNotifier( MNotificationCallback& aClient );
        
        /**
        * Set data for the UsernamePassword Dialog(s)
        * @param  aPasswordInfo    data to be filled
        * @param  aEapType         Eap type to be used
        * @param  aMap             Pointer to variant data
        * @param  aAuthMethod      Auth method to be used
        * return -
        */
        void SetUsernamePasswordDataL( 
            TEapDialogInfo* aPasswordInfo,
            TEapExpandedType& aEapType,
            CHbSymbianVariantMap* aMap,
            TDesC& aAuthMethod );
                
        
        /**
        * Set data for the query Dialog(s)
        * @param  aEapInfo         data to be filled
        * @param  aMap             Pointer to variant data
        * @param  aAuthMethod      Auth method to be used
        * return -
        */
        void SetQueryDialogDataL( 
            TEapDialogInfo* aEapInfo,
            CHbSymbianVariantMap* aMap,
            TDesC& aAuthMethod );
        
       /**
        * Set data for the Install Pac query Dialog(s)
        * @param  aEapInfo         data to be filled
        * @param  aMap             Pointer to variant data
        * return -
        */
        void SetFastInstallPacQueryDialogDataL( 
            TEapDialogInfo* aEapInfo,
            CHbSymbianVariantMap* aMap );
        
       /**
        * Set data for the Pac file query Dialog(s)
        * @param  aEapInfo         data to be filled
        * @param  aMap             Pointer to variant data
        * return -
        */
        void setFastPacFileQueryPwDialogDataL( 
            TEapDialogInfo* aEapInfo,
            CHbSymbianVariantMap* aMap );
        
       /**
        * Set data for the prov wait note Dialog(s)
        * @param  aMap                  Pointer to variant data
        * @param  aAuthProvWaitNote     Tells whether aut or unauth 
        * return -
        */
        void setFastProvWaitNoteDialogDataL( 
            CHbSymbianVariantMap* aMap,
            TBool aAuthProvWaitNote );
                    
       /**
        * Set data for the Password Dialog(s)
        * @param  aEapType         Eap type to be used
        * @param  aMap             Pointer to variant data
        * @param  aAuthMethod      Auth method to be used
        * return -
        */
        void SetPasswordQueryDataL( 
            TEapExpandedType& aEapType,
            CHbSymbianVariantMap* aMap,
            TDesC& aAuthMethod );
        
    private:
        /** Pointer to the device dialog interface for handling the dialog */
        CHbDeviceDialogSymbian* iDialog;
        /** The observer to handle the data received from the orbit dialog */
        CEapAuthObserver* iObserver;
        
        TEapDialogInfo* iEapInfo;
        
        // for callback
        MNotificationCallback& iClient;  
        
        /* Information if request was already completed, in case the
         * observer receives the data signal and the signal about closing the
         * dialog.
         */
        TBool iCompleted;
        
        /* Information if request was already cancelled.
         */
        TBool iCancelled;
        
    
    };

#endif //__EAPAUTHNOTIFIER_H__

