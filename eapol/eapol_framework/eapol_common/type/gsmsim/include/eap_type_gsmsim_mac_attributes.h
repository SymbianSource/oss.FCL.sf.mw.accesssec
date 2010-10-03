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
* %version: 7.1.2 %
*/

#if !defined(_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H_)
#define _EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H 
#elif defined(EAP_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H)
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H 
	#define EAP_C_FUNC_EXPORT_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_type_gsmsim_header.h"
#include "eap_type_all_types.h"

//--------------------------------------------------

/// These are the stored attributes for message authentication calculations.
class EAP_CLASS_VISIBILITY_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H eap_type_gsmsim_MAC_attributes_c
{
private:
	//--------------------------------------------------

	u8_t * m_MAC;                       ///< This is the pointer to MAC.
	u32_t m_MAC_size;                   ///< This is the size of the MAC.
	u8_t *m_data;                       ///< This is the pointer to the authenticated data. 
	u32_t m_data_length;                ///< This the length of the authenticated data.

	//--------------------------------------------------
public:
	//--------------------------------------------------

	virtual ~eap_type_gsmsim_MAC_attributes_c();

	eap_type_gsmsim_MAC_attributes_c();

	eap_type_gsmsim_MAC_attributes_c(
		u8_t * MAC,
		u32_t MAC_size,
		u8_t * const EAP_data,
		u32_t EAP_data_length);

	void init(
		u8_t * MAC,
		u32_t MAC_size,
		u8_t * const EAP_data,
		u32_t EAP_data_length);

	u8_t * get_MAC() const;

	void set_MAC(u8_t * MAC);

	u32_t get_MAC_size() const;

	eap_type_gsmsim_MAC_attributes_c * copy() const;

	u8_t * get_data() const;

	u32_t get_data_length();

	void set_data(u8_t * const data);

	//--------------------------------------------------
};


#endif //#if !defined(_EAP_TYPE_GSMSIM_MAC_ATTRIBUTES_H_)

//--------------------------------------------------



// End.
