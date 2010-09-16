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
* %version: 14.2.8 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 75 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_type_all.h"

#if defined(USE_EAP_TYPE_GSMSIM)
	#include "eap_type_gsmsim.h"
	#include "eap_am_type_gsmsim.h"
#endif
#if defined(USE_AKA_EAP_TYPE)
	#include "eap_type_aka.h"
#endif
#if defined(USE_MSCHAPV2_EAP_TYPE)
	#include "eap_type_mschapv2.h"
#endif
#if defined(USE_SECURID_EAP_TYPE)
	#include "eap_type_securid.h"
#endif
#if defined(USE_LEAP_EAP_TYPE)
	#include "eap_type_leap.h"
#endif
#if defined(USE_TLS_EAP_TYPE) || defined(USE_PEAP_EAP_TYPE)
	#include "eap_type_tls_peap.h"
	#include "tls_base_record.h"
	#include "tls_record.h"
	#include "tls_application_eap_core.h"
	#include "eap_am_type_tls_peap.h"
	#include "tls_am_services.h"
	#include "eap_core.h"
#endif
#if defined(USE_FAST_EAP_TYPE)
	#include "eap_type_tls_peap.h"
	#include "tls_base_record.h"
	#include "tls_record.h"
	#include "tls_application_eap_fast.h"
	#include "eap_am_type_tls_peap.h"
	#include "tls_am_services.h"
	#include "eap_core.h"
#endif
#if defined(USE_SAESIM_EAP_TYPE)
	#include "eap_type_saesim_core.h"
#endif
#if defined(USE_DUMMY_SIM_EAP_TYPE)
	#include "eap_type_dummy_sim.h"
#endif
#if defined(USE_EAP_SIMPLE_CONFIG)
	#include "simple_config_am_services.h"
	#include "eap_am_type_simple_config.h"
	#include "simple_config_base_record.h"
	#include "simple_config_record.h"
	#include "eap_type_simple_config.h"
#endif //#if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

//
EAP_C_FUNC_EXPORT eap_base_type_c * const new_eap_type(
	abs_eap_am_tools_c * const tools,
	abs_eap_base_type_c * const partner,
	const eap_type_value_e eap_type,
	const bool is_client_when_true,
	const eap_am_network_id_c * const receive_network_id
#if defined(USE_EAP_SIMPLE_CONFIG)
	, abs_eap_configuration_if_c * const configuration_if
#endif // #if defined(USE_EAP_SIMPLE_CONFIG)
	)
{
	EAP_TRACE_BEGIN(tools, TRACE_FLAGS_DEFAULT);
	eap_base_type_c *type = 0;

	if (tools == 0)
	{
		EAP_TRACE_ERROR(
			tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: new_eap_type(): parameter tools is NULL.\n")));
		EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}

	if (partner == 0)
	{
		EAP_TRACE_ERROR(
			tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: new_eap_type(): parameter partner is NULL.\n")));
		EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
		return 0;
	}

	if (receive_network_id == 0
		|| receive_network_id->get_source() == 0
		|| receive_network_id->get_destination() == 0)
	{
		EAP_TRACE_ERROR(
			tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: new_eap_type(): parameter receive_network_id is NULL.\n")));
		EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
		EAP_ASSERT_ANYWAY_TOOLS(tools);
		return 0;
	}

#if defined(USE_EAP_TYPE_GSMSIM)
	if (eap_type == eap_type_gsmsim)
	{
		eap_am_type_gsmsim_c * am_type_gsmsim = ::new_eap_am_type_gsmsim(
			tools,
			partner,
			is_client_when_true,
			receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_gsmsim == 0
			|| am_type_gsmsim->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_type(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_gsmsim_c(
			tools,
			partner,
			am_type_gsmsim,
			true,
			is_client_when_true,
			receive_network_id);
	}
	else
#endif //#if defined(USE_EAP_TYPE_GSMSIM)
#if defined(USE_AKA_EAP_TYPE)
	if (eap_type == eap_type_aka)
	{
		eap_am_type_aka_c * am_type_aka = ::new_eap_am_type_aka(
			tools,
			partner,
			is_client_when_true,
			receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_aka == 0
			|| am_type_aka->get_is_valid() == false)
		{
			delete am_type_aka;
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_type(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_aka_c(
			tools,
			partner,
			am_type_aka,
			true,
			is_client_when_true,
			receive_network_id);
	}
	else
#endif //#if defined(USE_AKA_EAP_TYPE)
#if defined(USE_MSCHAPV2_EAP_TYPE)
	if (eap_type == eap_type_mschapv2)
	{
		eap_am_type_mschapv2_c * am_type_mschapv2
			= ::new_eap_am_type_mschapv2(
				tools,
				partner,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_mschapv2 == 0
			|| am_type_mschapv2->get_is_valid() == false)
		{
			delete am_type_mschapv2;
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_type(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_mschapv2_c(
			tools,
			partner,
			am_type_mschapv2,
			true,
			is_client_when_true,
			receive_network_id);
	}
	else
#endif //#if defined(USE_MSCHAPV2_EAP_TYPE)
#if defined(USE_SECURID_EAP_TYPE)
	if (eap_type == eap_type_generic_token_card)
	{
		eap_am_type_securid_c * am_type_securid
			= ::new_eap_am_type_securid(
				tools,
				partner,
				eap_type,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_securid == 0
			|| am_type_securid->get_is_valid() == false)
		{
			delete am_type_securid;
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_type(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_securid_c(
			tools,
			partner,
			am_type_securid,
			true,
			eap_type,
			is_client_when_true,
			receive_network_id);
	}
	else
#endif //#if defined(USE_SECURID_EAP_TYPE)
#if defined(USE_LEAP_EAP_TYPE)
	if (eap_type == eap_type_leap)
	{
		eap_am_type_leap_c * am_type_leap
			= ::new_eap_am_type_leap(
				tools,
				partner,
				is_client_when_true,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_leap == 0
			|| am_type_leap->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_type(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_leap_c(
			tools,
			partner,
			am_type_leap,
			true,
			is_client_when_true,
			receive_network_id);
	}
	else
#endif //#if defined(USE_LEAP_EAP_TYPE)
#if defined(USE_TLS_EAP_TYPE)
	if (eap_type == eap_type_tls)
	{
		eap_am_type_tls_peap_c * am_type_tls_peap
			= ::new_eap_am_type_tls_peap(
				tools,
				partner,
				eap_type,
				is_client_when_true,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_tls_peap == 0
			|| am_type_tls_peap->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_record_c * const tls_record
			= new tls_record_c(
				tools,
				am_type_tls_peap,
				false,
				0,
				false,
				is_client_when_true,
				eap_type,
				receive_network_id);
		if (tls_record == 0
			|| tls_record->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_tls_peap_c(
			tools,
			partner,
			am_type_tls_peap,
			true,
			tls_record,
			true,
			is_client_when_true,
			eap_type,
			receive_network_id);
	}
	else
#endif //#if defined(USE_TLS_EAP_TYPE)
#if defined(USE_PEAP_EAP_TYPE)
	if (eap_type == eap_type_peap)
	{
		eap_am_type_tls_peap_c * am_type_tls_peap
			= ::new_eap_am_type_tls_peap(
				tools,
				partner,
				eap_type,
				is_client_when_true,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_tls_peap == 0
			|| am_type_tls_peap->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		eap_core_c * const eap_core
			= new eap_core_c(
				tools,
				0,
				is_client_when_true,
				receive_network_id,
				true);
		if (eap_core == 0
			|| eap_core->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new eap_core_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_application_c * const application
			= new tls_application_eap_core_c(
				tools,
				eap_core,
				true,
				is_client_when_true,
				eap_type,
				receive_network_id);
		if (application == 0
			|| application->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new tls_application_eap_core_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_record_c * const tls_record
			= new tls_record_c(
				tools,
				am_type_tls_peap,
				false,
				application,
				true,
				is_client_when_true,
				eap_type,
				receive_network_id);
		if (tls_record == 0
			|| tls_record->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_tls_peap_c(
			tools,
			partner,
			am_type_tls_peap,
			true,
			tls_record,
			true,
			is_client_when_true,
			eap_type,
			receive_network_id);
	}
	else
#endif //#if defined(USE_PEAP_EAP_TYPE)
#if defined(USE_TTLS_EAP_TYPE)
	if (eap_type == eap_type_ttls)
	{
		eap_am_type_tls_peap_c * am_type_tls_ttls
			= ::new_eap_am_type_tls_peap(
				tools,
				partner,
				eap_type,
				is_client_when_true,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_tls_ttls == 0
			|| am_type_tls_ttls->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		eap_core_c * const eap_core
			= new eap_core_c(
				tools,
				0,
				is_client_when_true,
				receive_network_id,
				true);
		if (eap_core == 0
			|| eap_core->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new eap_core_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_application_c * const application
			= new tls_application_eap_core_c(
				tools,
				eap_core,
				true,
				is_client_when_true,
				eap_type,
				receive_network_id);
		if (application == 0
			|| application->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new tls_application_eap_core_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_record_c * const tls_record
			= new tls_record_c(
				tools,
				am_type_tls_ttls,
				false,
				application,
				true,
				is_client_when_true,
				eap_type,
				receive_network_id);
		if (tls_record == 0
			|| tls_record->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_tls_peap_c(
			tools,
			partner,
			am_type_tls_ttls,
			true,
			tls_record,
			true,
			is_client_when_true,
			eap_type,
			receive_network_id);
	}
	else
#endif //#if defined(USE_TTLS_EAP_TYPE)
#if defined(USE_SAESIM_EAP_TYPE)
	if (eap_type == eap_type_saesim)
	{
		type = new eap_type_saesim_core_c(tools, partner, is_client_when_true);
	}
	else
#endif
#if defined(USE_DUMMY_SIM_EAP_TYPE)
	if (eap_type == eap_type_sim)
	{
		type = new eap_type_dummy_sim_c(tools, partner, is_client_when_true);
	}
	else
#endif
#if defined(USE_EAP_SIMPLE_CONFIG)
	if (eap_type == eap_expanded_type_simple_config.get_type())
	{
		eap_am_type_simple_config_c * am_type_simple_config
			= ::new_eap_am_type_simple_config(
				tools,
				partner,
				eap_type,
				is_client_when_true,
				receive_network_id,
				configuration_if); // Note this function is defined in the platform AM DLL.
		if (am_type_simple_config == 0
			|| am_type_simple_config->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_simple_config(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		simple_config_base_record_c * const simple_config_record
			= new simple_config_record_c(
				tools,
				am_type_simple_config,
				false,
				is_client_when_true,
				receive_network_id);
		if (simple_config_record == 0
			|| simple_config_record->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: simple_config_record_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_simple_config_c(
			tools,
			partner,
			am_type_simple_config,
			true,
			simple_config_record,
			true,
			is_client_when_true,
			eap_type,
			receive_network_id);
	}
	else
#endif //#if defined(USE_EAP_SIMPLE_CONFIG)
#if defined(USE_FAST_EAP_TYPE)
	if (eap_type == eap_type_fast)
	{
		eap_am_type_tls_peap_c * am_type_tls_peap
			= ::new_eap_am_type_tls_peap(
				tools,
				partner,
				eap_type,
				is_client_when_true,
				receive_network_id); // Note this function is defined in the platform AM DLL.
		if (am_type_tls_peap == 0
			|| am_type_tls_peap->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		eap_core_c * const eap_core
			= new eap_core_c(
				tools,
				0,
				is_client_when_true,
				receive_network_id,
				true);
		if (eap_core == 0
			|| eap_core->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new eap_core_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_application_c * const application
			= new tls_application_eap_fast_c(
				tools,
				eap_core,
				true,
				is_client_when_true,
				eap_type,
				receive_network_id,
				am_type_tls_peap,
				0);
		if (application == 0
			|| application->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new tls_application_eap_core_c(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		tls_base_record_c * const tls_record
			= new tls_record_c(
				tools,
				am_type_tls_peap,
				false,
				application,
				true,
				is_client_when_true,
				eap_type,
				receive_network_id);
		if (tls_record == 0
			|| tls_record->get_is_valid() == false)
		{
			EAP_TRACE_ERROR(
				tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: new_eap_am_type_tls_peap(): failed.\n")));
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}

		type = new eap_type_tls_peap_c(
			tools,
			partner,
			am_type_tls_peap,
			true,
			tls_record,
			true,
			is_client_when_true,
			eap_type,
			receive_network_id);
	}
	else
#endif //#if defined(USE_FAST_EAP_TYPE)
	{
		EAP_TRACE_ERROR(
			tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: new_eap_type(): EAP-type=0xfe%06x%08x=%s not supported in this module.\n"),
			eap_type.get_vendor_id(),
			eap_type.get_vendor_type(),
			eap_header_string_c::get_eap_type_string(eap_type)));
	}
	EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
	return type;
}

//--------------------------------------------------



// End.
