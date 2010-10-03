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

#if !defined(_EAP_AM_FILE_INPUT_SYMBIAN_H_)
#define _EAP_AM_FILE_INPUT_SYMBIAN_H_


#include "eap_tools.h"
#include "abs_eap_am_tools.h"
#include "eap_am_tools.h"
#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_FILE_INPUT_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_am_file_input.h"
#include <f32file.h>

//--------------------------------------------------

const u32_t EAP_AM_FILE_INPUT_BUFFER_SIZE = 1024;

/// This is interface to EAP file input.
/** The EAP file input is used in configuration file read operations.
 */
class EAP_CLASS_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_am_file_input_symbian_c
: public abs_eap_am_file_input_c
{

private:

	abs_eap_am_tools_c *m_am_tools;

	/// Flag tells this object is valid.
	bool m_is_valid;

	/// Handle to file session.
	RFs m_file_session;

	/// Hamdle to file.
	RFile m_File;

	/// Cache input buffer to reduce Symbian read operations.
	TBuf8<EAP_AM_FILE_INPUT_BUFFER_SIZE> * m_input_buffer;

	/// Offset of read point in the m_input_buffer.
	u32_t m_input_buffer_offset;

	// On purpose unimplemented constructors.
	eap_am_file_input_symbian_c(eap_am_file_input_symbian_c &source);
	const eap_am_file_input_symbian_c & operator=(const eap_am_file_input_symbian_c& source);

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	void set_is_valid();

	/**
	 * This function reads n bytes from file to buffer.
	 */
	eap_status_e file_read_buffer(
		eap_variable_data_c * const buffer,
		const u32_t required_bytes);

public:

	/**
	 * The destructor of the eap_am_file_input_symbian_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H virtual ~eap_am_file_input_symbian_c();

	/**
	 * The constructor of the eap_am_file_input_symbian_c does nothing special.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_am_file_input_symbian_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * This function checks the file of name file_name exists.
	 * It returns eap_status_ok if file exists
	 * in other cases some error status.
	 * @param file_name is the pathname of the tested file.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_exists(
		const eap_variable_data_c * const file_name);

	/**
	 * This function deletes the file of name if file_name exists.
	 * It returns eap_status_ok if file did exist and it was deleted
	 * in other cases some error status.
	 * @param file_nameis the pathname of the deleted file.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_delete(
		const eap_variable_data_c * const file_name);
	
	/**
	 * This function copies the file source_file_name to file target_file_name.
	 * @param target_file_name is the pathname of the target file.
	 * @param source_file_name is the pathname of the source file.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_copy(
		const eap_variable_data_c * const target_file_name,
		const eap_variable_data_c * const source_file_name);

	/**
	 * This function opens file of name file_name.
	 * @param file_name is the pathname of the opened file.
	 * @param dir is the I/O direction (eap_file_io_direction_read or eap_file_io_direction_write).
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_open(
		const eap_variable_data_c * const file_name,
		const eap_file_io_direction_e dir);

	/**
	 * This function closes the file.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_close();

	/**
	 * This function returns size of a file.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H u32_t file_size();

	/**
	 * This function reads data from file.
	 * Maximum size read is the buffer size.
	 * @param buffer must be initialised to reguired size.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_read(eap_variable_data_c * const buffer);

	/**
	 * This function write data to a file.
	 * Maximum size write is the buffer size.
	 * @param buffer includes the written data.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_write(const eap_variable_data_c * const buffer);

	/**
	 * This function reads line from file.
	 * @param The read line will be copied to line parameter.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_read_line(eap_variable_data_c * const line);

	/**
	 * This function reads word from file.
	 * @param The read word will be copied to word parameter.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e file_read_word(eap_variable_data_c * const word);


	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H bool get_is_valid();

	/**
	 * This function opens directory of name directory_name.
	 * @param file_name is the pathname of the opened directory.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e directory_open(
		const eap_variable_data_c * const directory_name);

	/**
	 * This function reads the files and directories from open directory.
	 * @param directory_list includes the stattus of each file and directory in open directory.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e directory_read(
		eap_array_c<abs_eap_file_stat_c> * const directory_list);

	/**
	 * This function closes the directory.
	 */
	EAP_FUNC_VISIBILITY_EAP_AM_FILE_INPUT_SYMBIAN_H eap_status_e directory_close();


}; // class eap_am_bloom_algorithm_c

#endif //#if !defined(_EAP_AM_FILE_INPUT_SYMBIAN_H_)

//--------------------------------------------------



// End.
