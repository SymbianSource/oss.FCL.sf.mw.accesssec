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

#if !defined(_EAP_NETWORK_ID_H_)
#define _EAP_NETWORK_ID_H_

#include "eap_tools.h"
#include "abs_eap_am_tools.h"
#include "eap_am_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_NETWORK_ID_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H 
	#define EAP_FUNC_EXPORT_EAP_AM_NETWORK_ID_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_NETWORK_ID_H 
#elif defined(EAP_EXPORT_EAP_AM_NETWORK_ID_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_NETWORK_ID_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_NETWORK_ID_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_NETWORK_ID_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_NETWORK_ID_H 
#endif
// End: added by script change_export_macros.sh.

/// This class stores the protocol layer network identity.
/**
 * A eap_am_network_id_c class.
 * Network addresses are handled through eap_am_network_id_c class.
 * It includes source and destination addresses and the type of packet. 
 * Addresses are mostly Ethernet addresses. Packet type is the type of Ethernet packet.
 * The eap_am_network_id class stores the addresses using the eap_variable_data objects.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_NETWORK_ID_H eap_am_network_id_c
{

private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This struct decreases the memory print of eap_am_network_id_c.
	class eap_am_network_id_impl_str
	{
	public:
		~eap_am_network_id_impl_str();

		eap_am_network_id_impl_str(
			abs_eap_am_tools_c * const tools);

		/// This is source address.
		eap_variable_data_c m_source;

		/// This is destination address.
		eap_variable_data_c m_destination;

		/// This is type of the packet. Mostly this is Ethernet type.
		u16_t m_type;

		/// This indicates whether this object was generated successfully.
		bool m_is_valid;
	};

	/// This is pointer to data of eap_am_network_id_c.
	/// This decreases memory print of eap_am_network_id_c.
	/// This decreases stack usage of EAP_Core.
	eap_am_network_id_impl_str *  m_data;

	eap_status_e initialize_members();

	/**
	 * The set_is_valid() function sets the state of the eap_core object valid.
	 * The eap_core object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H void set_is_valid();

public:

	/**
	 * The destructor does nothing extra. The buffers of each address are 
	 * freed in the destructor of the eap_variable_data class.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H virtual ~eap_am_network_id_c();

	/**
	 * This version initializes the object.
	 * @param tools parameter is pointer to the tools class.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_am_network_id_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * This version takes addresses as pointers to any data.
	 * This could be used to initialize addresses from the received packet.
	 * @param tools parameter is pointer to the tools class.
	 * @param source parameter is pointer to the source address.
	 * @param source_length parameter is length of the source address.
	 * @param destination parameter is pointer to the destination address.
	 * @param destination_length parameter is length of the destination address.
	 * @param type parameter is type of the packet. Mostly this is Ethernet type.
	 * @param free_id parameter indicates whether the source and destination buffers must be freed in destructors.
	 * @param writable_id parameter indicates whether the source and destination buffers are writable.
	 *
	 * NOTE the data buffers are NOT copied.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_am_network_id_c(
		abs_eap_am_tools_c * const tools,
		const void * const source,
		const u32_t source_length,
		const void * const destination,
		const u32_t destination_length,
		const u16_t type,
		const bool free_id,
		const bool writable_id);

	/**
	 * This version takes addresses as pointers to eap_variable_data_c.
	 * @param tools parameter is pointer to the tools class.
	 * @param source parameter is pointer to the source address.
	 * @param destination parameter is pointer to the destination address.
	 * @param type parameter is type of the packet. Mostly this is Ethernet type.
	 *
	 * NOTE the data buffers are NOT copied. This is used to swap addresses of existing
	 * eap_am_network_id_c object and create a new object using existing addresses.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_am_network_id_c(
		abs_eap_am_tools_c * const tools,
		const eap_variable_data_c * const source,
		const eap_variable_data_c * const destination,
		const u16_t type);

	/**
	 * This version uses the data from existing object.
	 * @param tools parameter is pointer to the tools class.
	 * @param network_id parameter is pointer to the existing object.
	 *
	 * NOTE this copies the addresses.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_am_network_id_c(
		abs_eap_am_tools_c * const tools,
		const eap_am_network_id_c * const network_id);

	/**
	 * This function uses the data from existing object.
	 * @param network_id parameter is pointer to the existing object.
	 *
	 * NOTE this copies the addresses.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_status_e set_copy_of_network_id(
		const eap_am_network_id_c * const network_id);

	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_status_e set_copy_of_am_network_id(
		const void * const source,
		const u32_t source_length,
		const void * const destination,
		const u32_t destination_length,
		const u16_t type);

	/**
	 * The get_is_valid() function returns the status of the eap_core object.
	 * True indicates the object is initialized succesfully.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H bool get_is_valid() const;

	/**
	 * The get_is_valid_data() function returns the status of the eap_core object.
	 * True indicates the object does include valid addresses.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H bool get_is_valid_data() const;

	/**
	 * The get_source_id() function returns pointer to the source address.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H const eap_variable_data_c * get_source_id() const;

	/**
	 * The get_destination_id() function returns pointer to the destination address.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H const eap_variable_data_c * get_destination_id() const;


	/**
	 * The get_source() function returns pointer to the source data.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H const u8_t * get_source() const;

	/**
	 * The get_destination() function returns pointer to the destination data.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H const u8_t * get_destination() const;


	/**
	 * The get_source_length() function returns length of the source address.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H u32_t get_source_length() const;

	/**
	 * The get_destination_length() function returns length of the destination address.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H u32_t get_destination_length() const;

	/**
	 * The get_type() function returns type of the packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H u16_t get_type() const;

	/**
	 * The get_network_id() function returns pointer to this.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H const eap_am_network_id_c * get_network_id() const;

	/**
	 * The copy() function copies the eap_am_network_id object.
	 * The data of addresses are copied to new buffers.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H eap_am_network_id_c * copy() const;

	/**
	 * Compare the objects are identical.
	 * @return false if data of objects differs.
	 * @return true if data of objects are the same.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H bool compare_network_id(const eap_am_network_id_c * const network_id) const;

	/**
	 * The get_type() function sets type of the packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H void set_type(const u16_t type);

	/**
	 * Resets the object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_NETWORK_ID_H void reset();
};


#endif //#if !defined(_EAP_NETWORK_ID_H_)

//--------------------------------------------------



// End.
