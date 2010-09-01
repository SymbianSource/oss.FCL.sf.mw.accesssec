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
* Description: This is the ECOM interface for EAP Plugin Configuration.
*
*/

/*
* %version: 13 %
*/

#ifndef __EAPPLUGINCONFIGURATIONIF_H__
#define __EAPPLUGINCONFIGURATIONIF_H__


// INCLUDES
#include <e32base.h>
#include <ecom/ecom.h>


// CONSTANTS
const TUid KEapPluginConfigInterfaceUid = {0x102072CA};


// CLASS DECLARATION
/**
* CEAPPluginConfigurationIf class
* ECOM interface for EAP PLugin Configuration.
*/
class CEAPPluginConfigurationIf : public CBase
    {
    public:
        inline static CEAPPluginConfigurationIf* NewL( 
                                                const TDesC8& aMatchString );
    
        inline virtual ~CEAPPluginConfigurationIf();
    
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
        virtual TInt EAPPluginConfigurationL( TDes& aWPAEAPPlugin, 
                                              const TUint32 aIapID, 
                                              const TDes& aConnectionName ) = 0;
                                         
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
        virtual TInt EAPPluginConfigurationL( TDes8& aWPAEnabledEAPPlugin, 
                                              TDes8& aWPADisabledEAPPlugin, 
                                              const TUint32 aIapID, 
                                              const TDes& aConnectionName ) = 0;

        /**
        * Shows the EAP type info.
        */
        virtual void ShowEAPTypeInfo() = 0;
    
        /**
        * Deletes all EAP types' settings for
        * the given IAP.
        */
        virtual void DeleteSettingsL( const TUint32 aIapID ) = 0;
    
        /**
        * Changes the index of the EAP settings for all EAP types    
        */
        virtual void ChangeIapIDL( const TUint32 aOldIapID, 
                                   const TUint32 aNewIapID ) = 0;

	    /**
        * Copies the EAP type settings to another ID
        */
	    virtual void CopySettingsL( const TUint32 aSourceIapID, 
                                    const TUint32 aDestinationIapID ) = 0;


    private: // Data    
        // This variable holds the instance identifier.
        TUid iDtor_ID_Key; 
    };
    

#include "EAPPluginConfigurationIf.inl" 
    
#endif      // __EAPPLUGINCONFIGURATIONIF_H__

// End of File
