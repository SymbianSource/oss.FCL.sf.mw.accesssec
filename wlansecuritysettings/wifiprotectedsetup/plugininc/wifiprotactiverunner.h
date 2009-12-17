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
* Description: Implements a state - machine like active object that controls Wi-Fi Protected Setup Process. 
*
*/


#ifndef C_WIFIPROTACTIVERUNNER_H
#define C_WIFIPROTACTIVERUNNER_H

// INCLUDES
#include <e32base.h>
#include <cmmanagerext.h>
#include <AknQueryDialog.h>
#include <AknProgressDialog.h>

#include "wifiprotdlgsplugin.h"
#include "wifiparams.h"
#include "wifiprotactiverunnercallback.h"


//FORWARD DECLARATIONS
class CWlanMgmtClient;
class CMDBSession;
class CWiFiProtConfirmationNoteDlg;
class CWiFiProtInitiateEasySetupDlg;
class CWlanScanInfo;
class CWiFiProtEnterPinDlg;
class CWEPSecuritySettings;
class RCmConnectionMethodExt;

//CONSTS
const TInt KMaxPINLength = 8; //is it really 8?
// ID of OfflineWlanNote dialog
const TUid KUidCOfflineWlanNoteDlg = { 0x101FD671 };

/**
* CWiFiProtActiveRunner
* State machine like object that manages Wi-Fi Protected setup ui process
* @since S60 v3.2
*/
class CWiFiProtActiveRunner : public CActive, public MProgressDialogCallback,
                                                     MActiveRunnerCallback
    {
    private:
    // States to control Wi-Fi Protected Setup sequence
        enum TWiFiProtStates
            {
            // Display 'Configure Automatically?' Dialog
            EWiFiProtAskConfigureAutomatically = 1,  
            // Display 'Initiate Easy Setup?' Dialog            
            EWiFiProtInitiateEasySetup,
            // If phone is in offline mode, continue with
            // "Create WLAN connection in offline mode?" confirmation
            EWifiProtOfflineQuery,
            // Display 'Enter PIN code' Dialog
            EWiFiProtUsePinCode,
            // Starting wait dialog
            EWiFiProtStartingWaitDlg,
            // Configuring (Creating temp iap and making a call to wlan
            // mgmt server )
            EWiFiProtConfiguring,
            // Wlan Mgmt server returned
            EWiFiProtWlanMgmtEngineReturned,
            // Creating iap from parameters from wlan mgmt server
            EWiFiProtCreateAllIaps,
            // Configuration finished
            EWiFiProtConfFinished,
            // Destroying wait note
            EWiFiProtDestroyWaitNote,            
            // Waiting for PIN query to exit
            EWiFiProtWaitForPINQuery,            
            // Wlan Scan
            EWiFiProtWlanScan,
            // Displaying Select Connection Dialog
            EWiFiProtSelectConnection,
            // Displaying final note about configured settings
            EWiFiProtSettingsConfNote,
            // Finished, exiting
            EWiFiProtFinished,
            // Cancelled, exiting
            EWiFiProtCancelled
            };
            
    // Asynchronous service to cancel
        enum TWiFiProtOutstandingRequest
            {
            EWiFiProtReqNone = 0,
            EWiFiProtReqConfirmDialog,
            EWiFiProtReqInitDialog,
            EWiFiProtReqWPS,
            EWiFiProtReqWlanScan           
            };
            
    public:
        /**
        * Two phased constructor
        * @param aPriority Active object priority
        */    
        static CWiFiProtActiveRunner* NewL( CWiFiProtDlgsPlugin* aParent,
                TInt aPriority = CActive::EPriorityStandard  );
        
        /**
        * Destructor
        */    
        ~CWiFiProtActiveRunner();

        
        /**
        * Starts Wi-Fi Protected Setup
        * @param aSSid contains SSid of the network we want to configure 
        * @param aCmManagerToUse - RCmManagerExt to use. Must pass this 
        * to avoid CmManager database
        * locking problems    
        */    
        void StartProtectedSetupAsyncL (  const TWlanSsid& aSSid,
                                                      RArray<TUint32>& aUids,
                                            RCmManagerExt& aCmManagerToUse );

        /**
        * Starts Wi-Fi Protected Setup in Connection creation mode
        * @param aSSid contains SSid of the network we want to configure 
        * @param aNetworkSettings the configured network's settings to be
        * returned 
        * @param aCmManagerToUse - RCmManagerExt to use. Must pass this 
        * to avoid CmManager database
        * locking problems
        * @return  possible return values are ok, cancel process and not use 
        * protected setup (No Automatic Setup).        
        */                                                
        void StartProtectedSetupConnL (
                                     const TWlanSsid& aSSid,
                                     TWlanProtectedSetupCredentialAttribute&
                                          aNetworkSettings,
                                     RCmManagerExt& aCmManagerToUse );
        
        /**
        * Starts Wi-Fi Protected Setup using CActiveSchedulerWait block
        * @param aSSid contains SSid of the network we want to configure 
        * @param aCmManagerToUse - RCmManagerExt to use. Must pass this 
        * to avoid CmManager database
        * locking problems
        * @return  possible return values are ok, cancel process and not use 
        * protected setup (No Automatic Setup).        
        */    
        WiFiProt::TWiFiReturn StartProtectedSetupL (  const TWlanSsid& aSSid,
                                                      RArray<TUint32>& aUids,
                                            RCmManagerExt& aCmManagerToUse );
        
        /**
         * When the process is cancelled by the client rather than
         * cancelled by the user, some things are taken care of
         * a bit differently.
         */
        void CancelByClient();
        
    private:


        /**
        * Shows the first dialog in the sequence
        */
        void ShowInitialDialogL (); 
        /**
         * Shows connect in offline -notification.
         */
        void ShowOfflineQuery ();
         /**
        * Shows the Initiate Easy Setup dialog
        */
        void ShowInitiateEasySetupDialogL (); 
           
         /**
        * Shows the 'Enter PIN on Wireless Station' dialog
        */    
        void ShowEnterPinOnStationDialogL();

        /**
        * Shows waiting dialog
        */     
        void ShowWaitingDialogL();
        
        /**
        * Shows waiting dialog and proceeds with the process
        */     
        void ShowWaitingDialogAndProceedL();
        
        /**
        * Shows 'settings configured' dialog
        * @param aWiFiProtState state to decide which note to display
        */     
        void ShowFinalNoteL();
        
        /**
        * wait note callback
        */
        void DialogDismissedL( TInt aButtonId );

        /**
        * Creates Temporary iap (cm) which contains parameters to be passed
        * to wlan engine
        * @param aTempServId Temporary iap service id          
        * @return TUint32 iap id (cm uid)
        */    
        TUint32 CreateTempIapL( TUint32& aTempServId );

        /**
        * Calls the active object that calls wlan engine's RunProtectedSetup
        * @param TUint32 aIap iap id (cm uid)
        */   
        void RunProtectedSetup( const TInt32 aIap );    

        /**
        * Constructor
        * @param aParent Parent object
        * @param aPriority Active object priority
        */
        CWiFiProtActiveRunner( CWiFiProtDlgsPlugin* aParent, TInt aPriority );
        
        /**
        * Second phase constructor
        */
        void ConstructL();

        /** From CActive */
        /**
        @see CActive::DoCancel
        */    
        virtual void DoCancel();
        
        /**
        @see CActive::RunL
        */        
        virtual void RunL();

        
        /**
        * Sets iNextWiFiProtState and completes the pending request
        * used to step forward in the 'state machine'
        * @param aNextState - the state to step to
        */
        void SetNextStateAndComplete( TWiFiProtStates aNextState,
                                      TInt aError = KErrNone );
        
        /**
        * Called from RunL in EWiFiProtConfiguring state
        * Starts configuring the connection methods
        */
        void ConfigureL();

        /**
        * Proceeds after DestroyWaitDialog or after PinQueryExitL and
        * checks error state and continues with Wlan availability 
        * scan if needed
        */
        void EvaluateResult();
        
        /**
        * Called from RunL in EWiFiProtConfFinished state
        * Destroys the wait dialog as configuring is complete
        */
        void DestroyWaitDialog();
 
        /*
        * Computes checksum number which is the last number of
        * the 8 digit PIN code passed to wlan mgmt engine
        * algorythm copied from Wi-Fi spec
        * @param aPin Pin code
        * @return last digit, to be appended to PIN
        */       
        TInt ComputeChecksum(TInt aPin);

        /*
        * Creates a single iap (from the first network's parameters),
        * and then repeats the process for each iap
        * The iap parameters at 0 index (in iIapParametersArray) will be
        * used to create an iap. passed to CreateIapL.
        */       
        void CreateAllIapsL();
        
        /**
        * Creates Connection Method using RCmManagerExt
        * The iap parameters at the given index (in iIapParametersArray)
        * will be used to create an iap. Then the parameters entry will
        * be deleted from iIapParametersArray
        * and the new iap's id will be added to iCmArray.
        * @param TInt aIndex index of the connection method (iap) to create
        * in iIapParametersArray
        * @return IapId of the cm
        */
        TUint32 CreateIapL( const TInt aIndex );
        
        /**
        * Sets iap settings to a given connection method object and saves it
        * @param TInt aIndex index of the connection method (iap) 
        * in iIapParametersArray
        * @param aCmToSet target connection method object 
        * @return IapId of the cm
        */        
        TUint32 SetIapDataL( const TInt aIndex, RCmConnectionMethodExt& aCmToSet );

        // calls DeleteTempIapL, and also steps the state machine
        void CleanupTempIapL();        

        /**
        * Deletes temporary iap
        */
        void DeleteTempIapL();

        /**
        * Returns wep format, ETrue if it is in hex
        * @param aLength Wep key length
        */
        TBool IsWepFormatHexL( TInt aLength );

        /**
        * Saves wep security settings from the 
        * given credential parameters
        * @param aCredentialAttribute credential parameters including wep
        * security settings data
        * @param aWlanServiceId Wlan service id
        * @param aDb Database session needed for saving
        * wep security settings
        */
        void SaveWepSecuritySettingsL(
                       TWlanProtectedSetupCredentialAttribute
                        aCredentialAttribute, 
                       TUint32 aWlanServiceId,
                       CommsDat::CMDBSession& aDb );

        /**
        * Handles the given error code by dispaying an error note
        * @param aErrorCode error code to handle
        */
        TBool HandleErrorL( TInt aErrorCode );

        /**
        * Steps into the next state of Wi-Fi Protected Setup sequence
        * called from RunL()
        */
        void HandleNoErrorL ();


        /**
        * From MActiveRunnerCallback
        * called when CWifiProtEnterPinDlg is finished
        * @param TInt aResponse can be KErrNone or KErrCancel
        */
        void PinQueryExitL( TInt aResponse );

        /**
        * Called by UsePinCodeLinkSelectedL when pin code mechanism
        * is selected. Sets iUsePin flag and completes Active Runner
        * (this) object
        */
        void DoUsePinCodeLinkSelectedL();

        /**
        * Starts wlan scan
        */
        void StartWlanScan();
        
        /**
        * Compares the fresh wlan networks list with the
        * items returned by WPS. Puts the available network indexes
        * into iAvailableNetworks
        */
        void CheckNetworkAvailabilityL();

        /*
        * Displays the Select Connection Dialog
        * When there are more connections available to use
        * (used in Create Connection Mode)
        */
        void SelectConnectionL();
        
        /*
        * Displays a note to show the user that 
        * no wlan networks were found during wlan scan
        */
        void ShowNoWlanNetworksNoteL();

        /*
        * Calls cancel on the possibly currently ongoing request
        */
        void CancelOngoingRequest();
        
        /**
        * Sets wep key
        * @param aWepSecSettings Wep security settings object
        * @param aWepKey Wep key to set
        * @param aKeyNumber number of wep key to set
        */
        void SetWepKeyL( CWEPSecuritySettings& aWepSecSettings,
                         TWlanWepKey& aWepKey, TInt aKeyNumber );    

    public:
        /**
        * Callback to handle pin code pin code mechanism link selection
        */    
        static TInt UsePinCodeLinkSelectedL( TAny* aObject );
        
    private:
        // reference to parent object
        CWiFiProtDlgsPlugin* iParent;
        // wait dialog
        CAknWaitDialog* iWaitDlg;  ///Owned
        // RCmManagerExt object for Cm Manager operations
        RCmManagerExt* iCmManagerExt; //NOT OWNED!!!
        // ETrue if connection is needed after the Wi-Fi Protected
        // setup.
        TBool iIsConnectionNeeded;
        // Array to store returned uids of created iaps (connection methods)
        RArray<TUint32>* iUids;//NOT OWNED!!!
        // flag to indicate that wait dialog was cancelled
        TBool iWaitDlgCancelled;
        // ssid of the network to setup
        TWlanSsid iSsid;
        // iap id of the temporary iap
        TUint32 iTempIapId ;
        // service id of the temporary iap
        TUint32 iTempServId ;
        // PIN code (holds a value only if PIN method is used)
        // for Wi-Fi Protected Setup authentication
        TBuf<KMaxPINLength> iPIN;
        // Wlan mgmt engine
        CWlanMgmtClient* iWlanMgmtEngine;
        // Next state, checked in RunL to control the setup process
        TWiFiProtStates iNextWiFiProtState;
        // return value
        WiFiProt::TWiFiReturn iReturn;
        // A flag to indicate that PIN method is used
        TBool iUsePin;
        // Holds the error code from wlan mgmt engine after 
        // our wlan mgmt server request is complete
        TInt iError;
        // Active Scheduler wait object to hold the process until we are 
        // complete
        CActiveSchedulerWait iWait;
        // Array to hold the connection methods which are created from 
        // the data returned from wlan mgmt engine
        RPointerArray<RCmConnectionMethodExt> iCmArray;//used to store cms
                                                    // before submitting them
        // The connection metod parameters returned from wlan mgmt engine
        CArrayFixSeg<TWlanProtectedSetupCredentialAttribute>*
                     iIapParametersArray; //parameters from wlan mgmt engine
        // ETrue if Pin Query Dialog is active
        TBool iPinQueryActive;
        // ETrue if a wait note is needed to be shown
        TBool iWaitNoteNeeded;
        // initiate setup dialog is stored to handle link selection callback,
        // not owned
        CWiFiProtInitiateEasySetupDlg* iInitDialog;
        // Wlan Scan Info
        CWlanScanInfo* iScanInfo;
        // List of available networks, contains indexes for iIapParametersArray
        RArray<TInt> iAvailableNetworks;
        // index of selected network in iAvailableNetworks
        TInt iSelectedNetworkIndex;
        // ongoing request to cancel if cancelled
        TWiFiProtOutstandingRequest iORequest;
        // Cancel called by user, cancel at next RunL cycle
        TBool iUserCancelled;
        // ETrue if the process is cancelled by the client.
        TBool iClientCancelled;
        // Flag to indicate that the 'use pin code' link was used
        // and we have to destroy the dialog later, because avkon crashes if
        // we do it in the callback (DoUsePinCodeLinkSelectedL)
        TBool iDestroyInitDialogLater;
        // not owned, just keeping pointer to handle cancel softkey removal
        CWiFiProtEnterPinDlg* iPinDlg;
        //pointer to network settings to be returned if WPS is used for 
        // connection creation 
        TWlanProtectedSetupCredentialAttribute* iNetworkSettings;
        // ETrue if the WPS process is used in synchronous mode
        TBool iSyncMode;
        // ETrue if phone is in offline mode.
        TBool iInOfflineMode;
        // Stores data for offline note. Used
        // only for writing result. Not read.
        TPckgBuf<TBool> iOfflineReply;
        // Interface to Notifier
        RNotifier iNotifier;
        // Pointer to the 1st confirmation dialog. Owned.
        CWiFiProtConfirmationNoteDlg* iConfirmationDialog;
        


    };

#endif //C_WIFIPROTACTIVERUNNER_H

// End of File
