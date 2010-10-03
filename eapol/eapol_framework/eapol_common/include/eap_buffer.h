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

#if !defined(_EAP_BUFFER_H_)
#define _EAP_BUFFER_H_

#include "eap_am_assert.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_BUFFER_H)
	#define EAP_CLASS_VISIBILITY_EAP_BUFFER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_BUFFER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_BUFFER_H 
	#define EAP_FUNC_EXPORT_EAP_BUFFER_H 
	#define EAP_C_FUNC_EXPORT_EAP_BUFFER_H 
#elif defined(EAP_EXPORT_EAP_BUFFER_H)
	#define EAP_CLASS_VISIBILITY_EAP_BUFFER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_BUFFER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_BUFFER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_BUFFER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_BUFFER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_BUFFER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_BUFFER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_BUFFER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_BUFFER_H 
	#define EAP_C_FUNC_EXPORT_EAP_BUFFER_H 
#endif
// End: added by script change_export_macros.sh.


//--------------------------------------------------

const u32_t EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH = 1514;

const u8_t EAP_MEM_GUARD_BYTE = 0x55;

#if defined(_DEBUG) && defined(USE_EAP_MEM_GUARD)

	const u32_t EAP_MEM_GUARD_LENGTH = 256u;

	#define EAP_MEM_GUARDS(buffer_size) \
		(EAP_MEM_GUARD_LENGTH+(buffer_size)+EAP_MEM_GUARD_LENGTH)

#else

	const u32_t EAP_MEM_GUARD_LENGTH = 0u;

	#define EAP_MEM_GUARDS(buffer_size) (buffer_size)

#endif //#if defined(_DEBUG) && defined(USE_EAP_MEM_GUARD)



enum eap_write_buffer_e
{
	eap_write_buffer
};


enum eap_read_buffer_e
{
	eap_read_buffer
};

enum eap_random_error_type
{
	eap_random_error_type_manipulate_byte = 0,
	eap_random_error_type_change_packet_length_longer,
	eap_random_error_type_change_packet_length_shorter,
	eap_random_error_type_none_keep_this_last_case,
};

//--------------------------------------------------

class abs_eap_am_tools_c;
class eapol_ethernet_header_wr_c;
class eapol_ethernet_header_rd_c;


/// Network packets are handled through eap_buf_chain_base_c class.
class EAP_CLASS_VISIBILITY_EAP_BUFFER_H eap_buf_chain_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This struct decreases the memory print of eap_buf_chain_base_c.
	struct eap_buf_chain_base_impl_str
	{
		/// This is the count of guard bytes allocated before and after the buffer.
		u32_t m_mem_guard_length;

		eap_variable_data_c * m_buffer;

		/// This is pointer to the next buffer. NOTE this is NOT used in current version.
		eap_buf_chain_base_c *m_next_buffer;

		/// This is used to test protocol with manipulated packets. This is used in testing.
		eap_random_error_type m_random_error_type;

		/// This is used to test protocol with manipulated packets. This is used in testing.
		u32_t m_send_packet_index;

		/// This the pointer of sender stack.
		/// This is used in testing.
		const void *m_stack_address;

		/// This indicates the buffer is initialized.
		bool m_is_valid;

		/// This is used to mark packet if it is manipulated. This is used in testing.
		bool m_is_manipulated;

		/// When this parameter is true eap_core_c activates re-transmission of this packet.
		/// When this parameter is false eap_core_c does not activate re-transmission of this packet.
		bool m_do_packet_retransmission;

		/// This is tells whether the sender is client or server.
		/// This is used in testing.
		bool m_is_client;

		/// This is used in testing.
		bool m_do_length_checks;

		/// This flag tells whether this packet must be encrypted (true) or not (false).
		/// Encryption means the WLAN data encryption on the air (WEP, TKIP or CCMP).
		/// Using this flag to tell the encryption allows the configuration of the
		/// temporal key beforehand the key is used.
		/// This is optimization to fasten the key configuration.
		bool m_encrypt;
	};

	/// This is pointer to data of eap_buf_chain_base_c.
	/// This decreases memory print of eap_buf_chain_base_c.
	/// This decreases stack usage of EAP_Core.
	eap_buf_chain_base_impl_str *  m_data;

	//--------------------------------------------------

	/**
	 * This function initializes the eap_buf_chain_base_c object.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e initialize(
		const u32_t mem_guard_length);

	/**
	 * Forses the inheritance.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H virtual void force_inheritance() = 0;

	/**
	 * Function checks the memory guard bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool check_guard_bytes(const u8_t * const guard) const;

	/**
	 * Function sets the memory guard bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_mem_guard_bytes();

	/**
	 * Function zeroes the data buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void reset_data_buffer();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/**
	 * @return Returns pointer to the tools object.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H abs_eap_am_tools_c * get_am_tools();

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * Function checks the all memory guard bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool check_guards() const;

	/**
	 * The destructor of the eap_buf_chain_base_c class checks memory guards
	 * and frees the allocated buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H virtual ~eap_buf_chain_base_c();

	/**
	 * The constructor of the eap_buf_chain_wr class initializes attributes using
	 * the parameters passes to it.
	 * @param eap_write_buffer_e separates the write and read-only constructors.
	 * @param tools parameter is pointer to the tools class.
	 * @param data is pointer to the buffer containing the message. 
	 * @param data_length parameter is count of bytes in the buffer.
	 * @param reset_data parameter indicates whether the data bytes must be set zero.
	 * @param free_buffer parameter indicates whether the destructor must free the data buffer.
	 * @param mem_guard_length indicates the length of guard bytes both pre-fix and post-fix.
	 *
	 * NOTE the buffer allocated from the stack or from the heap must allocate additional
	 * bytes for memory guards. The EAP_MEM_GUARDS(size) macro increases the size with count 
	 * of memory guard bytes. The example use of eap_buf_chain_wr is as follows.
	 * NOTE all sanity checks are ignored in the example.
	 *
	 * @code
	 * u8_t packet_buffer[EAP_MEM_GUARDS(EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH)];
	 * eap_buf_chain_wr_c response_packet(
	 *     eap_write_buffer, m_am_tools, packet_buffer,
	 *     sizeof(packet_buffer), true, false, EAP_MEM_GUARD_LENGTH);
	 * const u32_t eap_header_offset = get_type_partner()->get_header_offset(
	 *     &MTU, &trailer_length);
	 * eap_header_wr_c * const eap_response = (eap_header_wr_c * const)
	 *     response_packet.get_data_offset(eap_header_offset,
	 *         (EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH
	 *         -(eap_header_offset+ trailer_length)));
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_base_c(
		const eap_write_buffer_e, 
		abs_eap_am_tools_c * const tools,
		u8_t * const data, 
		const u32_t data_length, 
		const bool reset_data,
		const bool free_buffer, 
		const u32_t mem_guard_length);

	/**
	 * The constructor of the eap_buf_chain_wr class initializes attributes using
	 * the parameters passes to it.
	 * @param eap_read_buffer_e separates the write and read-only constructors.
	 * @param tools parameter is pointer to the tools class.
	 * @param data is pointer to the buffer containing the message. 
	 * @param data_length parameter is count of bytes in the buffer.
	 * @param free_buffer parameter indicates whether the destructor must free the data buffer.
	 *
	 * The example use of eap_buf_chain_wr is as follows.
	 * NOTE all sanity checks are ignored in the example.
	 *
	 * @code
	 * u8_t packet_buffer[EAP_MEM_GUARDS(EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH)];
	 * eap_buf_chain_rd_c response_packet(
	 *     eap_read_buffer, m_am_tools, packet_buffer,
	 *     sizeof(packet_buffer), false);
	 * const u32_t eap_header_offset = get_type_partner()->get_header_offset(
	 *     &MTU, &trailer_length);
	 * eap_header_rd_c * const eap_response = (eap_header_rd_c * const)
	 *     response_packet.get_data_offset(eap_header_offset,
	 *         (EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH
	 *         -(eap_header_offset+ trailer_length)));
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_base_c(
		const eap_read_buffer_e,
		abs_eap_am_tools_c * const tools,
		const u8_t * const data, 
		const u32_t data_length,
		const bool free_buffer);

	/**
	 * The constructor of the eap_buf_chain_wr class initializes attributes using
	 * the parameters passes to it.
	 * New buffer is allocated from heap.
	 * @param eap_write_buffer_e separates the write and read-only constructors.
	 * @param tools parameter is pointer to the tools class.
	 * @param data_length parameter is count of bytes in the buffer.
	 *
	 * The example use of eap_buf_chain_wr is as follows.
	 * NOTE all sanity checks are ignored in the example.
	 *
	 * @code
	 * eap_buf_chain_rd_c response_packet(
	 *     eap_write_buffer_e, m_am_tools,
	 *     PACKET_BUFFER_LENGTH);
	 * const u32_t eap_header_offset = get_type_partner()->get_header_offset(
	 *     &MTU, &trailer_length);
	 * eap_header_rd_c * const eap_response = (eap_header_rd_c * const)
	 *     response_packet.get_data_offset(eap_header_offset,
	 *         (PACKET_BUFFER_LENGTH
	 *         -(eap_header_offset+ trailer_length)));
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_base_c(
		const eap_write_buffer_e,
		abs_eap_am_tools_c * const tools,
		const u32_t data_length);

	/**
	 * The constructor of the eap_buf_chain_rd class initializes attributes using
	 * the parameters passes to it.
	 * New buffer is allocated from heap.
	 * @param eap_write_buffer_e separates the write and read-only constructors.
	 * @param tools parameter is pointer to the tools class.
	 * @param data_length parameter is count of bytes in the buffer.
	 *
	 * The example use of eap_buf_chain_wr is as follows.
	 * NOTE all sanity checks are ignored in the example.
	 *
	 * @code
	 * eap_buf_chain_rd_c response_packet(
	 *     eap_read_buffer, m_am_tools,
	 *     PACKET_BUFFER_LENGTH);
	 * const u32_t eap_header_offset = get_type_partner()->get_header_offset(
	 *     &MTU, &trailer_length);
	 * eap_header_rd_c * const eap_response = (eap_header_rd_c * const)
	 *     response_packet.get_data_offset(eap_header_offset,
	 *         (PACKET_BUFFER_LENGTH
	 *         -(eap_header_offset+ trailer_length)));
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_base_c(
		const eap_read_buffer_e,
		abs_eap_am_tools_c * const tools,
		const u32_t data_length);

	/**
	 * @return Returns count of memory guard bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u32_t get_mem_guard_length();

	/**
	 * The get_buffer_length() function returns the length of buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u32_t get_buffer_length() const;

	/**
	 * The get_data_length() function returns count of data bytes in the buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u32_t get_data_length() const;

	/**
	 * The get_data_offset() function returns pointer to the data in offset (p_offset).
	 * @param p_offset indicates the required offset.
	 * @param p_continuous_bytes indicates how many bytes in continuous memory is needed.
	 *
	 * NOTE user of the eap_buf_chain_wr class must obtain the pointer to the data using
	 * this or the get_data() function. These functions can handle the memory guard.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u8_t * get_data_offset(const u32_t p_offset, const u32_t p_continuous_bytes) const;

	/**
	 * The get_data() function function returns pointer to the data.
	 * @param p_continuous_bytes indicates how many bytes in continuous memory is needed.
	 *
	 * NOTE user of the eap_buf_chain_wr class must obtain the pointer to the data using
	 * this or the get_data_offset() function. These functions can handle the memory guard.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u8_t * get_data(const u32_t p_continuous_bytes) const;

	/**
	 * The set_buffer_length() function allocates the buffer of length bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e set_buffer_length(const u32_t length);

	/**
	 * The set_data_length() function set the data length in the buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e set_data_length(const u32_t length);

	/**
	 * The get_is_valid() function returns the status of the object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_is_valid() const;

	/**
	 * The get_is_valid() function returns the status of the
	 * data included in object.
	 * @return True indicates the object includes valid data.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_is_valid_data() const;

	/**
	 * The set_is_manipulated() function sets flag to indicate this packet is manipulated.
	 * This is used for testing purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_is_manipulated();

	/**
	 * The get_is_manipulated() function returns flag to indicate this packet is manipulated.
	 * This is used for testing purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_is_manipulated();

	/**
	 * This function sets the index of sent packet.
	 * This is used for testing purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_send_packet_index(const u32_t send_packet_index);

	/**
	 * This function returns the index of sent packet.
	 * This is used for testing purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u32_t get_send_packet_index();

	/**
	 * The set_random_error_type() function sets the type of manipulation of the packet.
	 * This is used for testing purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_random_error_type(eap_random_error_type error_type);

	/**
	 * The get_random_error_type() function returns the type of manipulation of the packet.
	 * This is used for testing purposes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_random_error_type get_random_error_type();

	/**
	 * The set_do_packet_retransmission() function sets the re-transmission flag of this packet.
	 * Packet will be re-transmitted by lower layer when do_packet_retransmission_when_true is true.
	 * Packet will not re-transmitted by lower layer when do_packet_retransmission_when_true is false.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_do_packet_retransmission(const bool do_packet_retransmission_when_true);

	/**
	 * The set_do_packet_retransmission() function gets the re-transmission flag of this packet.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_do_packet_retransmission();

	/**
	 * This sets whether the sender is client or server.
	 * This is used in testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_is_client(const bool is_client_when_true);

	/**
	 * This gets whether the sender is client or server.
	 * This is used in testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_is_client() const;

	/**
	 * This is used in testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_do_length_checks(const bool do_length_checks);

	/**
	 * This is used in testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_do_length_checks() const;


	/**
	 * This sets whether this packet must be encrypted (true) or not (false).
	 * Encryption means the WLAN data encryption on the air (WEP, TKIP or CCMP).
	 * Using this flag to tell the encryption allows the configuration of the
	 * temporal key beforehand the key is used.
	 * This is optimization to fasten the key configuration.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_encrypt(const bool encrypt_when_true);

	/**
	 * This gets whether this packet must be encrypted (true) or not (false).
	 * Encryption means the WLAN data encryption on the air (WEP, TKIP or CCMP).
	 * Using this flag to tell the encryption allows the configuration of the
	 * temporal key beforehand the key is used.
	 * This is optimization to fasten the key configuration.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H bool get_encrypt() const;


	/**
	 * This sets the pointer of sender stack.
	 * This is used in testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void set_stack_address(const void * const stack_address);

	/**
	 * This gets the pointer of sender stack.
	 * This is used in testing.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H const void * get_stack_address() const;

	/**
	 * The add_data() function adds data to the end of the buffer.
	 * If the buffer is empty the data is added to begin of the buffer.
	 * @param buffer points the data to be added.
	 * @param buffer_length is length of the buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e add_data(
		const void * const buffer,
		const u32_t buffer_length);

	/**
	 * The add_data() function adds data to the end of the buffer.
	 * If the buffer is empty the data is added to begin of the buffer.
	 * @param buffer points the data to be added.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e add_data(
		const eap_variable_data_c * const buffer);

	/**
	 * The add_data_to_offset() function adds data to the offset of the buffer.
	 * @param offset tells the place where data will begin.
	 * @param buffer points the data to be added.
	 * @param buffer_length is length of the buffer in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e add_data_to_offset(
		const u32_t offset,
		const void * const buffer,
		const u32_t buffer_length);

	/**
	 * The add_data() function adds data to the offset of the buffer.
	 * @param offset tells the place where data will begin.
	 * @param buffer points the data to be added.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_status_e add_data_to_offset(
		const u32_t offset,
		const eap_variable_data_c * const buffer);

	// 
	//--------------------------------------------------
}; // class eap_buf_chain_base_c



/// Write only network packets are handled through eap_buf_chain_base_c class.
/// Post-suffix _wr_c indicates the buffer has write attribute on.
/// The eap_buf_chain_wr_c class is derived from eap_buf_chain_base class.
class EAP_CLASS_VISIBILITY_EAP_BUFFER_H eap_buf_chain_wr_c
: public eap_buf_chain_base_c
{
private:

	/**
	 * Forses the inheritance.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void force_inheritance();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H virtual ~eap_buf_chain_wr_c();

	/**
	 * The costructor does nothing special. It just initializes all member attributes.
	 * This version uses preallocated buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_wr_c(
		const eap_write_buffer_e,
		abs_eap_am_tools_c * const tools,
		u8_t * const data,
		const u32_t data_length,
		const bool reset_data,
		const bool free_buffer,
		const u32_t mem_guard_length);

	/**
	 * The costructor does nothing special. It just initializes all member attributes.
	 * This version allocates buffer from heap.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_wr_c(
		const eap_write_buffer_e,
		abs_eap_am_tools_c * const tools,
		const u32_t data_length);

	/**
	 * The costructor does nothing special. It just initializes all member attributes.
	 * This version does not allocate buffer.
	 * You must call set_buffer_length() member function to allocate buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_wr_c(
		const eap_write_buffer_e,
		abs_eap_am_tools_c * const tools);

	/**
	 * @return Returns the pointer to the ethernet header.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H u8_t * get_ethernet_header();

	/**
	 * The copy() function copies the eap_buf_chain_wr object.
	 * Data is copied to new allocated buffer.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_wr_c * copy();

	// 
	//--------------------------------------------------
}; // class eap_buf_chain_wr_c


/// Read only network packets are handled through eap_buf_chain_rd_c class.
/// Post-suffix _rd_c indicates the buffer has read only attribute on.
/// The eap_buf_chain_rd_c class is derived from eap_buf_chain_base class.
class EAP_CLASS_VISIBILITY_EAP_BUFFER_H eap_buf_chain_rd_c
: public eap_buf_chain_base_c
{
private:

	/**
	 * Forses the inheritance.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H void force_inheritance();

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_buf_chain_rd_c class checks memory guards.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H virtual ~eap_buf_chain_rd_c();

	/**
	 * The constructor of the eap_buf_chain_wr class initializes attributes using
	 * the parameters passes to it.
	 * @param eap_read_buffer_e separates the write and read-only constructors.
	 * @param tools parameter is pointer to the tools class.
	 * @param data is pointer to the buffer containing the message. 
	 * @param data_length parameter is count of bytes in the buffer.
	 * @param free_buffer parameter indicates whether the destructor must free the data buffer.
	 *
	 * The example use of eap_buf_chain_wr is as follows.
	 * NOTE all sanity checks are ignored in the example.
	 *
	 * @code
	 * u8_t packet_buffer[EAP_MEM_GUARDS(EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH)];
	 * eap_buf_chain_rd_c response_packet(
	 *     eap_read_buffer, m_am_tools, packet_buffer,
	 *     sizeof(packet_buffer), false);
	 * const u32_t eap_header_offset = get_type_partner()->get_header_offset(
	 *     &MTU, &trailer_length);
	 * eap_header_rd_c * const eap_response = (eap_header_rd_c * const)
	 *     response_packet.get_data_offset(eap_header_offset,
	 *         (EAP_MAX_LOCAL_PACKET_BUFFER_LENGTH
	 *         -(eap_header_offset+ trailer_length)));
	 * @endcode
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_rd_c(
		const eap_read_buffer_e, 
		abs_eap_am_tools_c * const tools,
		const u8_t * const data, 
		const u32_t data_length,
		const bool free_buffer);

	/**
	 * The costructor does nothing special. It just initializes all member attributes.
	 * This version allocates buffer from heap.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H eap_buf_chain_rd_c(
		const eap_read_buffer_e,
		abs_eap_am_tools_c * const tools,
		const u32_t data_length);

	/**
	 * The get_data() function function returns pointer to the data.
	 * @param p_continuous_bytes indicates how many bytes in continuous memory is needed.
	 *
	 * NOTE user of the eap_buf_chain_wr class must obtain the pointer to the data using
	 * this or the get_data_offset() function. These functions can handle the memory guard.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H const u8_t * get_data(const u32_t p_continuous_bytes) const;

	/**
	 * The get_data_offset() function returns pointer to the data in offset (p_offset).
	 * @param p_offset indicates the required offset.
	 * @param p_continuous_bytes indicates how many bytes in continuous memory is needed.
	 *
	 * NOTE user of the eap_buf_chain_wr class must obtain the pointer to the data using
	 * this or the get_data() function. These functions can handle the memory guard.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H const u8_t * get_data_offset(const u32_t p_offset, const u32_t p_continuous_bytes) const;

	/**
	 * @return Returns the pointer to the ethernet header.
	 */
	EAP_FUNC_VISIBILITY_EAP_BUFFER_H const u8_t * get_ethernet_header() const;

	// 
	//--------------------------------------------------
}; // class eap_buf_chain_rd_c


#endif //#if !defined(_EAP_BUFFER_H_)

//--------------------------------------------------



// End.
