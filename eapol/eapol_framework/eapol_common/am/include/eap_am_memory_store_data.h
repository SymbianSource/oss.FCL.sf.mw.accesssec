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

#if !defined( _EAP_AM_TOOLS_MEMORY_STORE_DATA_H_ )
#define _EAP_AM_TOOLS_MEMORY_STORE_DATA_H_


#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_MEMORY_STORE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_STORE_DATA_H 
#elif defined(EAP_EXPORT_EAP_AM_MEMORY_STORE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_STORE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_STORE_DATA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_STORE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_STORE_DATA_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tlv_message_data.h"

class eap_variable_data_c;
class abs_eap_am_tools_c;


/// This class is base class for data stored to memory store.
/**
 * Here the functions eap_core_map_c template requires.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H eap_am_memory_store_tlv_data_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

	eap_tlv_message_data_c m_tlv_data;

	u32_t m_timer_id;

public:

	/**
	 * The destructor of the eap_am_memory_store_tlv_data_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H virtual ~eap_am_memory_store_tlv_data_c();

	/**
	 * The constructor of the eap_am_memory_store_tlv_data_c does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H eap_am_memory_store_tlv_data_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H eap_status_e copy_message_data(
		const eap_tlv_message_data_c * const tlv_data,
		const u32_t timer_id);

	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H u32_t get_timer_id() const;

	/**
	 * This function returns the pointer to the data.
	 * Empty message return NULL pointer.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H void * get_message_data() const;

	/**
	 * This function returns the length of the data.
	 * Empty message return zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H u32_t get_message_data_length() const;

	/**
	 * This function should increase reference count.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H void object_increase_reference_count();

	/**
	 * This function should first decrease reference count
	 * and second return the remaining reference count.
	 * Reference count must not be decreased when it is zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_DATA_H u32_t object_decrease_reference_count();
};

#endif //#if !defined( _EAP_AM_TOOLS_MEMORY_STORE_DATA_H_ )



// End.
