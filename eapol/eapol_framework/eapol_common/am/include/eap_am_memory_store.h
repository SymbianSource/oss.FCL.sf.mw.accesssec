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

#if !defined( _EAP_AM_MEMORY_STORE_H_ )
#define _EAP_AM_MEMORY_STORE_H_

//#if !defined(NO_EAP_AM_MEMORY_STORE)

#include "abs_eap_base_type.h"
#include "eap_am_memory_store_data.h"
#include "eap_core_map.h"
#include "eap_tlv_message_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_MEMORY_STORE_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_STORE_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_STORE_H 
#elif defined(EAP_EXPORT_EAP_AM_MEMORY_STORE_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_STORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_STORE_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_STORE_H 
#endif
// End: added by script change_export_macros.sh.



/// This class is base class for data stored to memory store.
/**
 * This class allows EAP objects store data to memory
 * between authentication sessions.
 */
class eap_am_memory_store_c
: public abs_eap_am_memory_store_data_c
, public abs_eap_base_timer_c
{
private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	eap_core_map_c<
		eap_am_memory_store_tlv_data_c,
		abs_eap_am_memory_store_data_c,
		eap_variable_data_c> m_store_new;

	// This is counter to get unique timer IDs for each data stored.
	u32_t m_timer_id_counter;

	/// This indicates whether this object was generated successfully.
	bool m_is_valid;

	// This is documented in abs_eap_stack_interface_c::set_is_valid().
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H void set_is_valid();

public:

	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H virtual ~eap_am_memory_store_c();

	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H eap_am_memory_store_c(
		abs_eap_am_tools_c * const tools);

	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H eap_status_e shutdown();

	// This is documented in abs_eap_stack_interface_c::get_is_valid().
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H bool get_is_valid();

	/// Memory store is visible only during the eap_am_tools_c object is alive.
	/// This function add flat data to memory store.
	/// You must format your data to eap_tlv_message_data_c object.
	/// Data is identified by key parameter.
	/// You can set timeout to data. Data will be automatically removed after timeout.
	/// Timeout value zero means no timeout is set.
	/// Serious WARNING: do use really good key values.
	/// Memory store is globally used by all EAP Core objects.
	/// Key must be good that other users do not use others data.
	/// Add the real data type as a string to the key and other identifiers
	/// that separate data between the other users that store same data type
	/// to the memory store.
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H virtual eap_status_e add_data(
		const eap_variable_data_c * const key,
		const eap_tlv_message_data_c * const data,
		const u32_t timeout);

	/// Memory store is visible only during the eap_am_tools_c object is alive.
	/// This function gets data from memory store.
	/// Data is returned in eap_tlv_message_data_c object.
	/// Data is identified by key parameter.
	/// Serious WARNING: do use really good key values.
	/// Memory store is globally used by all EAP Core objects.
	/// Key must be good that other users do not use others data.
	/// Add the real data type as a string to the key and other identifiers
	/// that separate data between the other users that store same data type
	/// to the memory store.
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H virtual eap_status_e get_data(
		const eap_variable_data_c * const key,
		eap_tlv_message_data_c * const data);

	/// Memory store is visible only during the eap_am_tools_c object is alive.
	/// This function removes data from memory store.
	/// Data is identified by key parameter.
	/// Serious WARNING: do use really good key values.
	/// Memory store is globally used by all EAP Core objects.
	/// Key must be good that other users do not use others data.
	/// Add the real data type as a string to the key and other identifiers
	/// that separate data between the other users that store same data type
	/// to the memory store.
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H eap_status_e remove_data(
		const eap_variable_data_c * const key);


	/**
	 * Function timer_expired() is called after the timer is elapsed.
	 * @param id and data are set by caller of abs_eap_am_tools::set_timer() function.
	 * @param id could be used to separate different timer events.
	 * @param data could be pointer to any data that is needed in timer processing.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H eap_status_e timer_expired(
		const u32_t id, void *data);

	/**
	 * This function is called when timer event is deleted.
	 * Initialiser of the data must delete the data.
	 * Only the initializer knows the real type of data.
	 * @param id could be used to separate different timer events.
	 * @param data could be pointer to any data that is needed in timer processing.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_STORE_H eap_status_e timer_delete_data(
		const u32_t id, void *data);
};

//#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)

#endif //#if !defined( _EAP_AM_MEMORY_STORE_H_ )



// End.
