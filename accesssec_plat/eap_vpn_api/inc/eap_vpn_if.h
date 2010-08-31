/*
* Copyright (c) 2005 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: EAP and WLAN authentication protocols.
*
*/

/*
* %version: 9.1.2 %
*/

#ifndef __EAPPLUGININTERFACE_H__
#define __EAPPLUGININTERFACE_H__

// INCLUDES
#include <ecom/ecom.h>
#include  "eap_vpn_if_uids.h"

class MAbsEapVpnInterface;

class TAbsEapVpnInterfaceParams
{
    public:
    MAbsEapVpnInterface*    iCaller;
    TBool                           iClient;
};

// FORWARD DECLARATIONS

/**
 * Class:       CEapVpnInterface
 *
 * Description: Custom ECOM interface definition. This interface is used by
 *              clients to load eap_vpn_if instance and use the defined generic functions
 */
class CEapVpnInterface :
    public CActive
{
public: // Constructors and destructor
	/**
	 * Function:   NewL
	 *
	 * Description: Wraps ECom object instantitation. Will return the
	 *              default interface implementation.
	 *
	 * Note:        This is not a "normal" NewL method, since normally NewL
	 *              methods are only defined for concrete classes.
	 *              Note that also implementations of this interface
	 *              provide NewL methods. They are the familiar NewL's,
	 *              which create instance of classes.
     */
	static CEapVpnInterface* NewL(MAbsEapVpnInterface* aCaller, TBool aClient);

    /**
     * Function:   NewL
     *
     * Description: Wraps ECom object instantitation. Will search for
     *              interface implementation, which matches to given
     *              aOperationName.
     *
     * @param       aType name of requested implementation. (This is not the eap type!)
     *              Implementations advertise their "name" as specified
     *              in their resource file field
     *                 IMPLEMENTATION_INFO::default_data.
     *
     * Note:        This is not a "normal" NewL method, since normally NewL
     *              methods are only defined for concrete classes.
     *              Note that also implementations of this interface provide
     *              NewL methods. They are the familiar NewL's, which create
     *              instance of classes.
     */
    static CEapVpnInterface* NewL(const TDesC8& aType, MAbsEapVpnInterface* aCaller, TBool aClient);

	/**
	 * Function:    ~CEapVpnInterfaceImplementation
	 *
	 * Description: Destroy the object
     */
	inline virtual ~CEapVpnInterface();
    
protected:
    
    CEapVpnInterface();

public:

    /**
     * Function:    StartL
     *
     * Description: Initializes the eap plugin
	 *
     * @param       aType name of requested eap type implementation.
     *
     */
    virtual TInt StartL(const TUint8 aEapType) = 0;

    /**
     * Function:    EapConfigure
     *
     * Description: Configures the eap plugin
	 *
     * @param       aManualUsername The username, if not zero
     * @param       aManualRealm The realm, if not zero
     * @param       aManualRealmPrefix The realm prefix, if not zero
     * @param       aHideInitialIdentity Scramble username, if true
     *
     */
    virtual TInt EapConfigure(TDesC8& aManualUsername, TDesC8& aManualRealm, TDesC8& aRealmPrefix, TBool aHideInitialIdentity) = 0;
    
	/**
	 * Function:    QueryIdentity
	 *
	 * Description: Ask the identity
     */
	virtual TInt QueryIdentity() = 0;

    /**
	 * Function:    EapInbound
	 *
	 * Description: Handle incoming Eap message
	 *
     * @param       aMessage incoming eap message.
     *              
     */
    virtual TInt EapInbound(const TDesC8& aMessage) = 0;

    virtual void RunL()=0;
    virtual void DoCancel() = 0;

private:
   /** iDtor_ID_Key Instance identifier key. When instance of an
	 *               implementation is created by ECOM framework, the
	 *               framework will assign UID for it. The UID is used in
	 *               destructor to notify framework that this instance is
	 *               being destroyed and resources can be released.
     */
	TUid                            iDtor_ID_Key;
	};

// This includes the implementation of the instantiation functions and
// destructor
#include "eap_vpn_if.inl"

#endif
