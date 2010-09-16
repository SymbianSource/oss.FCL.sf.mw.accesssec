/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  This class stores the information on loaded EAP-type plugin.
*
*/

/*
* %version: 5 %
*/

#if !defined(_EAP_LOADED_TYPE_H_)
#define _EAP_LOADED_TYPE_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_LOADED_TYPE_H)
	#define EAP_CLASS_VISIBILITY_EAP_LOADED_TYPE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_LOADED_TYPE_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_LOADED_TYPE_H 
	#define EAP_FUNC_EXPORT_EAP_LOADED_TYPE_H 
	#define EAP_C_FUNC_EXPORT_EAP_LOADED_TYPE_H 
#elif defined(EAP_EXPORT_EAP_LOADED_TYPE_H)
	#define EAP_CLASS_VISIBILITY_EAP_LOADED_TYPE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_LOADED_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_LOADED_TYPE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_LOADED_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_LOADED_TYPE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_LOADED_TYPE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_LOADED_TYPE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_LOADED_TYPE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_LOADED_TYPE_H 
	#define EAP_C_FUNC_EXPORT_EAP_LOADED_TYPE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eap_am_plugin.h"
#include "eap_process_tlv_message_data.h"
#include <EapTypePlugin.h>

/** @file */

/// This class stores the information on loaded EAP-type plugin.
class EAP_CLASS_VISIBILITY_EAP_LOADED_TYPE_H eap_loaded_type_c
{

private:

	// ----------------------------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	CEapTypePlugin * const m_type_plugin;

	const eap_type_value_e m_eap_type;

	const u32_t m_index_type;

	const u32_t m_index;

	// ----------------------------------------------------------------------

public:

	// ----------------------------------------------------------------------

	// Destructor will delete type_plugin. So pass only object allocated from heap.
	eap_loaded_type_c(
		abs_eap_am_tools_c * const tools,
		CEapTypePlugin * const type_plugin,
		const eap_type_value_e eap_type,
		const u32_t index_type,
		const u32_t index);

	virtual ~eap_loaded_type_c();

	i32_t compare(const eap_loaded_type_c * const right);

	CEapTypePlugin * get_type_plugin();

	eap_type_value_e get_eap_type() const;

	u32_t get_index_type() const;

	u32_t get_index() const;

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_EAP_LOADED_TYPE_H_)


//--------------------------------------------------
// End
