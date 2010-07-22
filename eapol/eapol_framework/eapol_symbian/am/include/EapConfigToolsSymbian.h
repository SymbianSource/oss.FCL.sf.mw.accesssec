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
* %version: 1 %
*/

#if !defined(_EAP_CONFIG_TOOLS_SYMBIAN_H_)
#define _EAP_CONFIG_TOOLS_SYMBIAN_H_

class abs_eap_am_tools_c;
class eap_file_config_c;

class EapConfigToolsSymbian
{

public:

	// ----------------------------------------------------------------------

	static eap_status_e EapReadDefaultConfigFileSymbian(
		abs_eap_am_tools_c * const aAmTools,
		eap_file_config_c ** const aFileconfig);

};

#endif //#if !defined(_EAP_CONFIG_TOOLS_SYMBIAN_H_)

//--------------------------------------------------
// End.
