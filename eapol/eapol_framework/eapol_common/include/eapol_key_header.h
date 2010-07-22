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
* %version: %
*/

#if !defined(_EAPOL_KEY_HEADER_H_)
#define _EAPOL_KEY_HEADER_H_

#include "eapol_header.h"
#include "eap_general_header_base.h"


/// Enumeration of EAPOL-Key descriptor type field.
enum eapol_key_descriptor_type_e
{
	eapol_key_descriptor_type_none = 0,
	eapol_key_descriptor_type_RC4 = 1,
	eapol_key_descriptor_type_RSNA = 2, ///< @{ Check RSNA Descriptor Type value. 802.1X should define this value. This is our assuption based on traces. }
	eapol_key_descriptor_type_WPA = 0xfe, ///< WPA uses this value.
};


#endif //#if !defined(_EAPOL_KEY_H_)

//------------------------------------------------------



// End.
