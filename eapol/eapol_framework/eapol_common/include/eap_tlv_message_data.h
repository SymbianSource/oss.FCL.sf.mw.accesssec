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

#if !defined(_EAP_TLV_MESSAGE_DATA_H_)
#define _EAP_TLV_MESSAGE_DATA_H_

#include "eap_am_types.h"
#include "eap_tools.h"
#include "eap_array.h"
#include "eap_tlv_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TLV_MESSAGE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H 
	#define EAP_FUNC_EXPORT_EAP_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_TLV_MESSAGE_DATA_H 
#elif defined(EAP_EXPORT_EAP_TLV_MESSAGE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TLV_MESSAGE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TLV_MESSAGE_DATA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TLV_MESSAGE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_TLV_MESSAGE_DATA_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


//----------------------------------------------------------------------------


/// This class defines message data composed of Attribute-Value Pairs (See eap_tlv_header_c).
/**
 * Here is a figure of message data composed of Attribute-Value Pairs (See eap_tlv_header_c).
 * Value data follows eap_tlv_message_data_c.
 * @code
 *  EAP-TLV-message data:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Type                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Length = 8                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Value 1                          |
 * +-+-                                                         -+-+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Type                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Length = 4                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Value 2                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Type                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Length = 4                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Value 3                          |
 * +-+-                                                         -+-+
 * |                                                               |
 * +-+-                                                         -+-+
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * NOTE, the length of value could be anythin between 0 ... (2^32)-1.
 * Only the free memory limits the length of the value.
 * There are no padding between Attribute-Value Pairs.
 * The next Attribute-Value Pair starts exactly after the previous
 * Value of previous Attribute-Value Pair.
 * @endcode
 * 
 */
class EAP_CLASS_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_tlv_message_data_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	eap_variable_data_c m_message_data;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_tlv_message_data_c class does nothing.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H virtual ~eap_tlv_message_data_c();

	/**
	 * The constructor of the eap_tlv_message_data_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_tlv_message_data_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * This function should increase reference count.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H void object_increase_reference_count();

	/**
	 * This function should first decrease reference count
	 * and second return the remaining reference count.
	 * Reference count must not be decreased when it is zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H u32_t object_decrease_reference_count();

	/**
	 * This function returns the pointer to the data.
	 * Empty message return NULL pointer.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H void * get_message_data() const;

	/**
	 * This function returns the length of the data.
	 * Empty message return zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H u32_t get_message_data_length() const;

	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e allocate_message_data_buffer(
		const u32_t approximate_buffer_requirement);

	/**
	 * This function copies message data.
	 * Data must be formatted as EAP-TLV-message data.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e copy_message_data(
		const u32_t length,
		const void * const value);

	/**
	 * This function sets message data.
	 * Note the data is referenced not copied.
	 * Data must be formatted as EAP-TLV-message data.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e set_message_data(
		const u32_t length,
		const void * const value);

	/**
	 * This function adds data to message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e add_message_data(
		const eap_tlv_type_t type,
		const u32_t length,
		const void * const data);

	/**
	 * This function adds array of data to message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e add_message_data_array(
		const eap_tlv_type_t type,
		const u32_t length_of_each_data_block,
		eap_array_c<eap_variable_data_c> * const data_array);
	
	/**
	 * This function adds header of structured data to message.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e add_message_header(
		const eap_tlv_type_t type,
		const u32_t length);

	/**
	 * This function parses eap_tlv_header_c blocks from message to tlv_blocks.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e parse_message_data(
		eap_array_c<eap_tlv_header_c> * const tlv_blocks);

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H bool get_is_valid();

	/**
	 * This function allocates buffer to message of specified type.
	 * Function returns pointer to the value field of specified length.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_MESSAGE_DATA_H eap_status_e allocate_message_buffer(
		const eap_tlv_type_t type,
		const u32_t length,
		void * * const buffer);

	// 
	//--------------------------------------------------
}; // class eap_tlv_message_data_c


//--------------------------------------------------

#endif //#if !defined(_EAP_TLV_MESSAGE_DATA_H_)



// End.
