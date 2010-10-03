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

#if !defined(_EAP_VARIABLE_DATA_H_)
#define _EAP_VARIABLE_DATA_H_

#include "eap_am_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_VARIABLE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_VARIABLE_DATA_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H 
	#define EAP_FUNC_EXPORT_EAP_VARIABLE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_VARIABLE_DATA_H 
#elif defined(EAP_EXPORT_EAP_VARIABLE_DATA_H)
	#define EAP_CLASS_VISIBILITY_EAP_VARIABLE_DATA_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_VARIABLE_DATA_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_VARIABLE_DATA_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_VARIABLE_DATA_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_VARIABLE_DATA_H 
	#define EAP_C_FUNC_EXPORT_EAP_VARIABLE_DATA_H 
#endif
// End: added by script change_export_macros.sh.
//#include "eap_am_memory.h"
#include "eap_am_assert.h"
#include "eap_status.h"

//--------------------------------------------------

class abs_eap_am_tools_c;


/// This class stores any data in byte array.
class EAP_CLASS_VISIBILITY_EAP_VARIABLE_DATA_H eap_variable_data_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. @see abs_eap_am_tools_c
	abs_eap_am_tools_c * const m_am_tools;

	/// This struct decreases the memory print of eap_variable_data_c.
	struct eap_variable_data_impl_str
	{
		/// This is pointer to the buffer.
		u8_t *m_buffer;

		/// This indicates the length of the buffer.
		u32_t m_buffer_length;

		/// This indicates the start of the data in the buffer.
		u32_t m_real_data_start_index;

		/// This indicates the length of data in the buffer.
		u32_t m_real_data_length;

		/// This indicates the buffer is initialized. The attribute m_buffer points 
		/// to a memory buffer which length is m_buffer_length bytes.
		bool m_is_valid;

		/// This indicates the buffer will be freed in destructor.
		bool m_free_buffer;

		/// This indicates the buffer pointed by m_buffer can be modified.
		bool m_is_writable;
	};

	/// This is pointer to data of eap_variable_data_c.
	/// This decreases memory print of eap_variable_data_c.
	/// This decreases stack usage of EAP_Core.
	eap_variable_data_impl_str *  m_data;


	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e initialize_members();

	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e allocate_buffer(
		const u32_t required_buffer_length);

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Destructor of the eap_variable_data class will release 
	 * the buffer if attribute m_free_buffer is true.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H virtual ~eap_variable_data_c();

	/**
	 * Constructor takes only one parameter called tools.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_variable_data_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * Constructor takes five parameters.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param buffer is pointer to the buffer.
	 * @param buffer_length is size of the buffer.
	 * @param free_buffer indicates whether the buffer must be freed in the destructor.
	 * @param is_writable indicates whether the buffer is writable.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_variable_data_c(
		abs_eap_am_tools_c * const tools,
		const void * const buffer,
		const u32_t buffer_length,
		bool free_buffer,
		bool is_writable);


	/**
	 * The get_is_valid() function returns the status of the eap_variable_data object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H bool get_is_valid() const;


	/**
	 * The get_is_valid_data() function returns the status of the
	 * data included in eap_variable_data object.
	 * Note the object may include zero length data, and that is valid data.
	 * @return True indicates the object includes valid data.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H bool get_is_valid_data() const;

	/**
	 * The set_is_valid() function sets the state of the eap_variable_data object valid.
	 * The eap_variable_data_c object calls this function after it is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H void set_is_valid();

	/**
	 * The set_is_invalid() function sets the state of the eap_variable_data object invalid.
	 * The eap_variable_data_c object calls this function after it is uninitialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H void set_is_invalid();

	/**
	 * This function returns flag that indicates whether this
	 * buffer is writeble (true) or read only (false).
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H bool get_is_writable() const;

	/**
	 * The get_data_offset() function returns the pointer to the buffer.
	 * @param offset is offset from the begin of the buffer.
	 * @param buffer_length is required count of bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u8_t * get_buffer_offset(
		const u32_t offset,
		const u32_t buffer_length) const;

	/**
	 * The get_buffer() function returns the pointer to the buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u8_t * get_buffer(const u32_t buffer_length) const;

	/**
	 * The get_data_offset() function returns the pointer to the data.
	 * @param offset is offset from the begin of the data.
	 * @param data_length is required count of bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u8_t * get_data_offset(
		const u32_t offset,
		const u32_t data_length) const;

	/**
	 * The get_data() function returns the pointer to the begin of the data.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u8_t * get_data(const u32_t data_length) const;


	/**
	 * The get_data() function returns the pointer to the begin of the data.
	 * This function assumes the whole data is needed.
	 * User should test the validity of object and the length of the data before use of it.
	 * The purpose of this function is reduce code size.
	 */
#if defined(USE_EAP_INLINE_FUNCTIONS)
	EAP_INLINE u8_t * get_data() const
	{

#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)
		if (m_data != 0
			&& m_data->m_is_valid == true)
		{
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)

			return m_data->m_buffer + m_data->m_real_data_start_index;

#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)
		}
		else
		{
			return 0;
		}
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)

	}

#else

	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u8_t * get_data() const;

#endif //#if defined(USE_EAP_INLINE_FUNCTIONS)


	/**
	 * The get_data_length() function returns the count of bytes stored to the buffer.
	 */
#if defined(USE_EAP_INLINE_FUNCTIONS)
	EAP_INLINE u32_t get_data_length() const
	{

#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)
		if (m_data != 0
			&& m_data->m_is_valid == true)
		{
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)

			return m_data->m_real_data_length;

#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)
		}
		else
		{
			return 0u;
		}
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)

	}

#else

	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u32_t get_data_length() const;

#endif //#if defined(USE_EAP_INLINE_FUNCTIONS)


	/**
	 * The get_buffer_length() function returns the size of the buffer.
	 */
#if defined(USE_EAP_INLINE_FUNCTIONS)

	EAP_INLINE u32_t get_buffer_length() const
	{

#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)
		if (m_data != 0
			&& m_data->m_is_valid == true)
		{
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)

			return m_data->m_buffer_length;

#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)
		}
		else
		{
			return 0u;
		}
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS_RUNTIME_CHECKS)

	}

#else

	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u32_t get_buffer_length() const;

#endif //#if defined(USE_EAP_INLINE_FUNCTIONS)


	/**
	 * The reset_start_offset_and_data_length() function sets the begin offset of the data to zero
	 * and the length of data to zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e reset_start_offset_and_data_length();

	/**
	 * The set_start_offset() function sets the begin offset of the data to index.
	 * With this function data in the begin of the buffer can be removed
	 * without any copy operations.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_start_offset(const u32_t index);

	/**
	 * The set_data_length() function changes the length of the data.
	 * @param length is count of bytes in the buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_data_length(
		const u32_t length);

	/**
	 * The set_buffer() function initializes the eap_variable_data object
	 * using existing buffer.
	 * @param buffer is pointer to the buffer.
	 * @param buffer_length is size of the buffer.
	 * @param free_buffer indicates whether the buffer must be freed in the destructor.
	 * @param is_writable indicates whether the buffer is writable.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_buffer(
		const void * const buffer,
		const u32_t buffer_length,
		bool free_buffer,
		bool is_writable);

	/**
	 * The set_buffer() function initializes the eap_variable_data object
	 * using existing buffer.
	 * @param buffer is pointer to the buffer.
	 * @param buffer_length is size of the buffer.
	 * @param free_buffer indicates whether the buffer must be freed in the destructor.
	 * @param is_writable indicates whether the buffer is writable.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_buffer(
		void * const buffer,
		const u32_t buffer_length,
		bool free_buffer,
		bool is_writable);

	/**
	 * The set_buffer() function initializes the eap_variable_data object
	 * using existing buffer. Note the data will be in the same buffer.
	 * Data can be modified through both eap_variable_data objects.
	 * @param buffer is pointer to the buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_buffer(
		const eap_variable_data_c * const buffer);

	/**
	 * The set_copy_of_buffer() function copies the data of the buffer.
	 * @param buffer points the data to be copied.
	 * @param buffer_length is length of the buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_copy_of_buffer(
		const void * const buffer,
		const u32_t buffer_length);

	/**
	 * The set_copy_of_buffer() function copies the data of the buffer.
	 * The first version copies data pointed by parameter buffer.
	 * @param buffer points the data to be copied.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_copy_of_buffer(
		const eap_variable_data_c * const buffer);

	/**
	 * The set_buffer_length() function sets length ot the buffer
	 * atleast to buffer_length bytes.
	 * If the buffer is empty or less than buffer_length bytes, length of the buffer is set to buffer_length bytes.
	 * If the buffer includes data, data is kept in the buffer.
	 * @param buffer points the data to be added.
	 * @param buffer_length is length of the buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e set_buffer_length(
		const u32_t buffer_length);

	/**
	 * The add_data() function adds data to the end of the buffer.
	 * If the buffer is empty the data is added to begin of the buffer.
	 * @param buffer points the data to be added.
	 * @param buffer_length is length of the buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e add_data(
		const void * const buffer,
		const u32_t buffer_length);

	/**
	 * The add_data() function adds data to the end of the buffer.
	 * If the buffer is empty the data is added to begin of the buffer.
	 * @param buffer points the data to be added.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e add_data(
		const eap_variable_data_c * const buffer);

	/**
	 * The add_data_to_offset() function adds data to the offset of the buffer.
	 * @param offset tells the place where data will begin.
	 * @param buffer points the data to be added.
	 * @param buffer_length is length of the buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e add_data_to_offset(
		const u32_t offset,
		const void * const buffer,
		const u32_t buffer_length);

	/**
	 * The add_data() function adds data to the offset of the buffer.
	 * @param offset tells the place where data will begin.
	 * @param buffer points the data to be added.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e add_data_to_offset(
		const u32_t offset,
		const eap_variable_data_c * const buffer);

	/**
	 * The add_end_null() function adds 16-bit null ('\0\0') to the end of the buffer.
	 * This does not increase the data length.
	 * This function is usefull when null terminated strings are stored to
	 * eap_variable_data_c object.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e add_end_null();

	/**
	 * The reset() function resets the eap_variable_data object.
	 * Memory of the buffer is freed if the m_free_buffer attribute is true.
	 * Object does not include data after this call and get_is_valid_data()
	 * returns false.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e reset();

	/**
	 * The init() function initializes the eap_variable_data object.
	 * @param length is length of buffer in bytes that is allocated.
	 * Buffer is set empty, data length is set zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_status_e init(
		const u32_t length);

	/**
	 * The copy() function copies the eap_variable_data object and data.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H eap_variable_data_c * copy() const;


	/**
	 * The compare_length() function compares first compare_length bytes of the objects.
	 * @return Function returns zero when first compare_length bytes of the data are equal.
	 * If the data of the caller object is shorter than compare_length bytes
	 * or the first different byte of the caller is smaller the function returns negative value.
	 * If the data of the parameter object is shorter than compare_length bytes
	 * or the first different byte of the caller is larger the function returns positive value.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H i32_t compare_length(
		const void * const data,
		const u32_t data_length,
		const u32_t compare_length_of_data) const;

	/**
	 * The compare_length() function compares first compare_length bytes of the objects.
	 * @return Function returns zero when first compare_length bytes of the data are equal.
	 * If the data of the caller object is shorter than compare_length bytes
	 * or the first different byte of the caller is smaller the function returns negative value.
	 * If the data of the parameter object is shorter than compare_length bytes
	 * or the first different byte of the caller is larger the function returns positive value.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H i32_t compare_length(
		const eap_variable_data_c * const data,
		const u32_t compare_length_of_data) const;

	/**
	 * The compare() function compares the objects.
	 * @return Function returns zero when data lengths and the data are equal.
	 * If the data of the caller object is shorter or the first different byte
	 * of the caller is smaller the function returns negative value.
	 * If the data of the caller object is longer or the first different byte
	 * of the caller is larger the function returns positive value.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H i32_t compare(
		const void * const data,
		const u32_t data_length) const;

	/**
	 * The compare() function compares the objects.
	 * @return Function returns zero when data lengths and the data are equal.
	 * If the data of the caller object is shorter or the first different byte
	 * of the caller is smaller the function returns negative value.
	 * If the data of the caller object is longer or the first different byte
	 * of the caller is larger the function returns positive value.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H i32_t compare(
		const eap_variable_data_c * const data) const;


	/**
	 * The hash() function returns HASH-value calculated from the data.
	 * @return Maximum returned value is size-1. Minimum returned value is zero.
	 */
	EAP_FUNC_VISIBILITY_EAP_VARIABLE_DATA_H u32_t hash(
		const u32_t size) const;

	//--------------------------------------------------
}; // class eap_variable_data_c


#endif //#if !defined(_EAP_VARIABLE_DATA_H_)

// End.
