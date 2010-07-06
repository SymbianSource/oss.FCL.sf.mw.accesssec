/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  Some tools used in Symbian.
*
*/

/*
* %version: 6 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 725 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_config.h"
#include "eap_file_config.h"
#include "eap_am_file_input_symbian.h"
#include "eap_automatic_variable.h"
#include "EapConfigToolsSymbian.h"

#include "EapConversion.h"

#include "EapPluginTools.h"

//--------------------------------------------------

eap_status_e EapConfigToolsSymbian::EapReadDefaultConfigFileSymbian(
	abs_eap_am_tools_c * const aAmTools,
	eap_file_config_c ** const aFileconfig)
{
	EAP_TRACE_BEGIN(aAmTools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		aAmTools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eapol_read_default_config_file_symbian()\n")));
	EAP_TRACE_RETURN_STRING(aAmTools, "returns: eapol_read_default_config_file_symbian()");

	TInt error(KErrNone);
	eap_status_e status(eap_status_ok);

	(*aFileconfig) = 0;

#if defined(USE_EAP_FILECONFIG)
	{
		eap_am_file_input_symbian_c * const fileio = new eap_am_file_input_symbian_c(aAmTools);

		eap_automatic_variable_c<eap_am_file_input_symbian_c> automatic_fileio(aAmTools, fileio);

		if (fileio != 0
			&& fileio->get_is_valid() == true)
		{
			EAP_TRACE_DEBUG(
				aAmTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Initialize file configuration.\n")));

			eap_variable_data_c config_file_name(aAmTools);

			{
				TFileName aPrivateDatabasePathName;

				TRAP(error, EapPluginTools::GetPrivatePathL(
					aPrivateDatabasePathName));
				if (error != KErrNone)
				{
					eap_status_e status(aAmTools->convert_am_error_to_eapol_error(error));

					EAP_TRACE_DEBUG(
						aAmTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: EapPluginTools::GetPrivatePathL(): failed %d=%s.\n"),
						status,
						eap_status_string_c::get_status_string(status)));
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}

				_LIT(FILECONFIG_FILENAME, "eap.conf");

				aPrivateDatabasePathName.Append(FILECONFIG_FILENAME);

				error = CEapConversion::ConvertFromTDesCToInternal(
					aAmTools,
					aPrivateDatabasePathName,
					&config_file_name);
				if (error != KErrNone)
				{
					eap_status_e status(aAmTools->convert_am_error_to_eapol_error(error));

					EAP_TRACE_DEBUG(
						aAmTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: CEapConversion::ConvertFromTDesCToInternal(): failed %d=%s.\n"),
						status,
						eap_status_string_c::get_status_string(status)));
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}
			}

			eap_variable_data_c file_name_c_data(aAmTools);

			{
				eap_const_string const FILECONFIG_DRIVE_C = "c:";

				status = file_name_c_data.set_copy_of_buffer(
					FILECONFIG_DRIVE_C,
					aAmTools->strlen(FILECONFIG_DRIVE_C));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}

				status = file_name_c_data.add_data(&config_file_name);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}

				status = file_name_c_data.add_end_null();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}
			}

			eap_variable_data_c file_name_z_data(aAmTools);

			{
				eap_const_string const FILECONFIG_DRIVE_Z = "z:";

				status = file_name_z_data.set_copy_of_buffer(
					FILECONFIG_DRIVE_Z,
					aAmTools->strlen(FILECONFIG_DRIVE_Z));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}

				status = file_name_z_data.add_data(&config_file_name);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}

				status = file_name_z_data.add_end_null();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(aAmTools, status);
				}
			}



			if (status == eap_status_ok)
			{
				// Disable traces because this could fail. In most cases there are no configuration file on C: disk,
				u32_t saved_trace_mask =  aAmTools->get_trace_mask();
				aAmTools->set_trace_mask(eap_am_tools_c::eap_trace_mask_none);

				// First try open from C: disk.
				status = fileio->file_open(
					&file_name_c_data,
					eap_file_io_direction_read);

				// Enable traces because the next should not fail. Always there are configuration file on Z: disk,
				aAmTools->set_trace_mask(saved_trace_mask);

				if (status == eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						aAmTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("Opens configure file %s\n"),
						file_name_c_data.get_data(file_name_c_data.get_data_length())));
				}
				else
				{
					// Second try open from Z: disk.
					status = fileio->file_open(
						&file_name_z_data,
						eap_file_io_direction_read);
					if (status == eap_status_ok)
					{
						EAP_TRACE_DEBUG(
							aAmTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("Opens configure file %s\n"),
							 file_name_z_data.get_data(file_name_z_data.get_data_length())));
					}
				}

				if (status == eap_status_ok)
				{
					// Some of the files were opened.

					(*aFileconfig) = new eap_file_config_c(aAmTools);
					if ((*aFileconfig) != 0
						&& (*aFileconfig)->get_is_valid() == true)
					{
						status = (*aFileconfig)->configure(fileio);
						if (status != eap_status_ok)
						{
							EAP_TRACE_DEBUG(
								aAmTools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("ERROR: Configure read from %s failed.\n"),
								file_name_c_data.get_data(file_name_c_data.get_data_length())));
						}
						else
						{
							EAP_TRACE_DEBUG(
								aAmTools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("Configure read from %s\n"),
								file_name_c_data.get_data(file_name_c_data.get_data_length())));
						}
					}
					else
					{
						// No file configuration.
						delete (*aFileconfig);
						(*aFileconfig) = 0;

						EAP_TRACE_DEBUG(
							aAmTools,
							TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: Cannot create configure object for file %s\n"),
							file_name_c_data.get_data(file_name_c_data.get_data_length())));
					}
				}
				else
				{
					EAP_TRACE_DEBUG(
						aAmTools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("ERROR: Cannot open configure file neither %s nor %s\n"),
						file_name_c_data.get_data(file_name_c_data.get_data_length()),
						file_name_z_data.get_data(file_name_z_data.get_data_length())));
				}
			}
		}
		else
		{
			EAP_TRACE_DEBUG(
				aAmTools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("Skips file configuration.\n")));
		}
	}
#endif //#if defined(USE_EAP_FILECONFIG)


	EAP_TRACE_END(aAmTools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(aAmTools, status);
}

//--------------------------------------------------
// End.
