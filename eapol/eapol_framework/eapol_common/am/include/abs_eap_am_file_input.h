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

#if !defined(_ABS_EAP_AM_FILE_INPUT_H_)
#define _ABS_EAP_AM_FILE_INPUT_H_


#include "eap_tools.h"
#include "eap_array.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_FILE_INPUT_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_FILE_INPUT_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_FILE_INPUT_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_FILE_INPUT_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_FILE_INPUT_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_FILE_INPUT_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_FILE_INPUT_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_FILE_INPUT_H 
#endif
// End: added by script change_export_macros.sh.


//--------------------------------------------------

enum eap_file_io_direction_e
{
	eap_file_io_direction_read,
	eap_file_io_direction_write,
};

//--------------------------------------------------

enum eap_file_type_e
{
	eap_file_type_none,
	eap_file_type_file,
	eap_file_type_directory,
};

//--------------------------------------------------

class eap_variable_data_c;


class abs_eap_file_stat_c
{
private:

public:

	virtual ~abs_eap_file_stat_c()
	{
	}

	abs_eap_file_stat_c()
	{
	}

	virtual const eap_variable_data_c * const get_file_name() const = 0;

	virtual const eap_file_type_e get_file_type() const = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() const = 0;
};

//--------------------------------------------------

/// This is interface to EAP file input.
/** The EAP file input is used in configuration file read operations.
 */
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_FILE_INPUT_H abs_eap_am_file_input_c
{

private:

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	virtual void set_is_valid() = 0;

public:

	/**
	 * The destructor of the abs_eap_am_file_input_c class does nothing special.
	 */
	virtual ~abs_eap_am_file_input_c()
	{
	}

	/**
	 * The constructor of the abs_eap_am_file_input_c does nothing special.
	 */
	abs_eap_am_file_input_c()
	{
	}

	/**
	 * This function checks the file of name file_name exists.
	 * It returns eap_status_ok if file exists
	 * in other cases some error status.
	 * @param file_nameis the pathname of the tested file.
	 */
	virtual eap_status_e file_exists(const eap_variable_data_c * const file_name) = 0;

	/**
	 * This function deletes the file of name if file_name exists.
	 * It returns eap_status_ok if file did exist and it was deleted
	 * in other cases some error status.
	 * @param file_nameis the pathname of the deleted file.
	 */
	virtual eap_status_e file_delete(const eap_variable_data_c * const file_name) = 0;

	/**
	 * This function copies the file source_file_name to file target_file_name.
	 * @param target_file_name is the pathname of the target file.
	 * @param source_file_name is the pathname of the source file.
	 */
	virtual eap_status_e file_copy(
		const eap_variable_data_c * const target_file_name,
		const eap_variable_data_c * const source_file_name) = 0;

	/**
	 * This function opens file of name file_name.
	 * @param file_name is the pathname of the opened file.
	 * @param dir is the I/O direction (eap_file_io_direction_read or eap_file_io_direction_write).
	 */
	virtual eap_status_e file_open(
		const eap_variable_data_c * const file_name,
		const eap_file_io_direction_e dir) = 0;

	/**
	 * This function closes the file.
	 */
	virtual eap_status_e file_close() = 0;

	/**
	 * This function returns size of a file.
	 */
	virtual u32_t file_size() = 0;

	/**
	 * This function reads data from a file.
	 * Maximum size read is the buffer size.
	 * @param buffer must be initialised to reguired size.
	 */
	virtual eap_status_e file_read(eap_variable_data_c * const buffer) = 0;

	/**
	 * This function write data to a file.
	 * Maximum size write is the buffer size.
	 * @param buffer includes the written data.
	 */
	virtual eap_status_e file_write(const eap_variable_data_c * const buffer) = 0;

	/**
	 * This function reads line from file.
	 * @param The read line will be copied to line parameter.
	 */
	virtual eap_status_e file_read_line(eap_variable_data_c * const line) = 0;

	/**
	 * This function reads word from file.
	 * @param The read word will be copied to word parameter.
	 */
	virtual eap_status_e file_read_word(eap_variable_data_c * const word) = 0;


	/**
	 * This function opens directory of name directory_name.
	 * @param file_name is the pathname of the opened directory.
	 */
	virtual eap_status_e directory_open(
		const eap_variable_data_c * const directory_name) = 0;

	/**
	 * This function reads the files and directories from open directory.
	 * @param directory_list includes the stattus of each file and directory in open directory.
	 */
	virtual eap_status_e directory_read(
		eap_array_c<abs_eap_file_stat_c> * const directory_list) = 0;

	/**
	 * This function closes the directory.
	 */
	virtual eap_status_e directory_close() = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

	/**
	 * Function creates an object on a platform.
	 */
	static abs_eap_am_file_input_c * new_abs_eap_am_file_input_c(
		abs_eap_am_tools_c * const tools);

}; // class abs_eap_am_file_input_c

#endif //#if !defined(_ABS_EAP_AM_FILE_INPUT_H_)

//--------------------------------------------------



// End.
