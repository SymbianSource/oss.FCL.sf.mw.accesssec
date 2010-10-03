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

#if !defined(_EAP_GENERAL_HEADER_BASE_H_)
#define _EAP_GENERAL_HEADER_BASE_H_


#include "eap_am_assert.h"
#include "eap_am_tools.h"
#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_GENERAL_HEADER_BASE_H)
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_HEADER_BASE_H 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_HEADER_BASE_H 
#elif defined(EAP_EXPORT_EAP_GENERAL_HEADER_BASE_H)
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_HEADER_BASE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_HEADER_BASE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_GENERAL_HEADER_BASE_H 
	#define EAP_C_FUNC_EXPORT_EAP_GENERAL_HEADER_BASE_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

/** This is general base class defining the view to packet header.
 */
class EAP_CLASS_VISIBILITY_EAP_GENERAL_HEADER_BASE_H eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to the header buffer.
	u8_t * m_header_buffer;

	/// This is length of the header buffer.
	u32_t m_header_buffer_length;

#if defined(USE_EAP_ERROR_TESTS)
	/// This flag tells whether protocol detected error on packet.
	/// This is used in error testing.
	/// Value of this attribute is initialized to true.
	/// Protocol should change attribute value to false
	/// after it accepts this packet.
	bool m_error_detected;
#endif //#if defined(USE_EAP_ERROR_TESTS)

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	/// NOTE the header buffer is not deleted here.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H virtual ~eap_general_header_base_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of the packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H eap_general_header_base_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns the pointer to the offset of the data of the packet.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H u8_t * get_header_offset(const u32_t offset, const u32_t data_length) const;

	/// This function returns the pointer to the data of the packet.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H u8_t * get_header_buffer(const u32_t data_length) const;

	/// This function sets the buffer of the packet.
	/// The header_buffer parameter is pointer to buffer of the packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H void set_header_buffer(u8_t * const header_buffer, const u32_t header_buffer_length);

	/// This function returns the length of the header buffer.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H u32_t get_header_buffer_length() const;

	/// This function returns validity of the object.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H bool get_is_valid() const;

	/// This function returns pointer to the tools object.
	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H abs_eap_am_tools_c * get_am_tools() const;

	/// This function checks the validity of derived header.
	virtual eap_status_e check_header() const = 0;


#if defined(USE_EAP_ERROR_TESTS)

	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H void set_error_detected(const bool error_detected);

	EAP_FUNC_VISIBILITY_EAP_GENERAL_HEADER_BASE_H bool get_error_detected();

#endif //#if defined(USE_EAP_ERROR_TESTS)

	// 
	//--------------------------------------------------
}; // class eap_general_header_base_c


#if defined(USE_EAP_ERROR_TESTS)

	#define EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(destination, source) \
		{ \
			(destination)->set_error_detected((source)->get_error_detected()); \
		}

	#define EAP_GENERAL_HEADER_SET_ERROR_DETECTED(packet, true_or_false) \
		{ \
			(packet)->set_error_detected((true_or_false)); \
		}

#else

	#define EAP_GENERAL_HEADER_COPY_ERROR_PARAMETERS(destination, source)

	#define EAP_GENERAL_HEADER_SET_ERROR_DETECTED(packet, true_or_false)

#endif //#if defined(USE_EAP_ERROR_TESTS)


#endif //#if !defined(_EAP_GENERAL_HEADER_BASE_H_)

//--------------------------------------------------



// End.
