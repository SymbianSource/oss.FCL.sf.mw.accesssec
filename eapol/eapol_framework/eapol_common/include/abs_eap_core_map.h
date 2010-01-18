/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 4 %
*/

#if !defined(_ABS_EAP_TYPE_MAP_H_)
#define _ABS_EAP_TYPE_MAP_H_


/// This class is the interface to partner class of the eap_core_map_c class.
/// This declares the pure virtual member functions eap_core_map_c class could call.
/// Currently this interface is empty. No functions are defined.
class EAP_EXPORT abs_eap_core_map_c
{
private:
	//--------------------------------------------------

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the abs_eap_core_map class does nothing special.
	 */
	virtual ~abs_eap_core_map_c()
	{
	}

	/**
	 * The constructor of the abs_eap_core_map class does nothing special.
	 */
	abs_eap_core_map_c()
	{
	}

	//--------------------------------------------------
}; // class abs_eap_core_map_c

#endif //#if !defined(_ABS_EAP_TYPE_MAP_H_)

//--------------------------------------------------



// End.
