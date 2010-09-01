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
* Description: Header file of EAP Plugin Configuration
*
*/

/*
* %version: 16 %
*/

#ifndef __EAPPLUGINCONFIGURATION_H__
#define __EAPPLUGINCONFIGURATION_H__


// INCLUDES
#include <e32base.h>

#include "EAPPluginConfigurationIf.h"
#include "EAPPluginConfigUid.h"
#include "EAPPluginList.h"
#include "EapSettings.h"


// CLASS DECLARATION
/**
* CEAPPluginConfiguration class
*/
class CEAPPluginConfiguration : public CEAPPluginConfigurationIf
    {
    public:
        static CEAPPluginConfiguration* NewL();
        static CEAPPluginConfiguration* NewLC();
    
        ~CEAPPluginConfiguration();
    
        /**
        * Load the EAP Plugin configuration
        * @param    aWPAEAPPlugin   The list of EAPs in use as it was read from
        *                           WlanEapList column of WLANServiceTable. In 
        *                           output it contains the new list as it has 
        *                           to be written in the same column of 
        *                           database.
        * @param    aConnectionName The name of the connection.
        * @return   The ID of the button pressed to close configuration: 
        *           typically EAknSoftkeyBack for back, EAknCmdExit for a 
        *           request of exit or EEikCmdExit for a request of shutdown
        */
        TInt EAPPluginConfigurationL( TDes& aWPAEAPPlugin, 
                                      const TUint32 aIapID, 
                                      const TDes& aConnectionName );    
    
        /**
        * Load the EAP Plugin configuration (with expanded EAP types)
        * @param    aWPAEnabledEAPPlugin   The list of enabled EAPs in use as 
        *                           it was read from WlanEnabledEapList column 
        *                           of WLANServiceTable. In output it contains 
        *                           the new list as it has to be written in the 
        *                           same column of database.
        * @param    aWPADisabledEAPPlugin   The list of disabled EAPs in use as
        *                           it was read from WlanDisabledEapList column 
        *                           of WLANServiceTable. In output it contains 
        *                           the new list as it has to be written in the 
        *                           same column of database.
        * @param    aConnectionName The name of the connection.
        * @return   The ID of the button pressed to close configuration: 
        *           typically EAknSoftkeyBack for back, EAknCmdExit for a 
        *           request of exit or EEikCmdExit for a request of shutdown
        */
        TInt EAPPluginConfigurationL( TDes8& aWPAEnabledEAPPlugin, 
                                      TDes8& aWPADisabledEAPPlugin, 
                                      const TUint32 aIapID, 
                                      const TDes& aConnectionName );
    
        /**
        * Shows the EAP type info.
        */
        void ShowEAPTypeInfo();    

        /**
        * Deletes all EAP types' settings for
        * the given IAP.
        */
        void DeleteSettingsL( const TUint32 aIapID );
    
        /**
        * Changes the index of the EAP settings for all EAP types    
        */
        void ChangeIapIDL( const TUint32 aOldIapID, const TUint32 aNewIapID );
    
        /**
        * Copies the EAP type settings to another ID
        */
        void CopySettingsL( const TUint32 aSourceIapID, 
                            const TUint32 aDestinationIapID );

    private:
        void ConstructL();
        CEAPPluginConfiguration();
        void LoadPluginInfoL( TDes& aWPAEAPPlugin, REAPPluginList& aPlugins );
        void LoadPluginInfoL( TDes8& aWPAEnabledEAPPlugin, 
                              TDes8& aWPADisabledEAPPlugin, 
                              REAPPluginList& aPlugins );
        
        void SavePluginInfoL( TDes& aWPAEAPPlugin, REAPPluginList& aPlugins );
        void SavePluginInfoL( TDes8& aWPAEnabledEAPPlugin, 
                              TDes8& aWPADisabledEAPPlugin, 
                              REAPPluginList& aPlugins );
                              

        TInt MoveEAPType( EAPSettings::TEapType aEapType, TInt aPos );

        TInt MoveEAPType( const TDesC8& aEapType, TInt aPos );
		
    private: // Data
            // Resource file offset.
        TInt        iResOffset; 
        TUint32        iIapId;
        RImplInfoPtrArray iEapArray;
    };
    
    
#endif      // __EAPPLUGINCONFIGURATION_H__

// End of File
