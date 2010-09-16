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

#if !defined(_EAP_ARRAY_ALGORITHMS_H_)
#define _EAP_ARRAY_ALGORITHMS_H_

#include "eap_am_memory.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_ARRAY_ALGORITHMS_H)
	#define EAP_CLASS_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_ARRAY_ALGORITHMS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_ARRAY_ALGORITHMS_H 
	#define EAP_FUNC_EXPORT_EAP_ARRAY_ALGORITHMS_H 
	#define EAP_C_FUNC_EXPORT_EAP_ARRAY_ALGORITHMS_H 
#elif defined(EAP_EXPORT_EAP_ARRAY_ALGORITHMS_H)
	#define EAP_CLASS_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_ARRAY_ALGORITHMS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_ARRAY_ALGORITHMS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_ARRAY_ALGORITHMS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_ARRAY_ALGORITHMS_H 
	#define EAP_C_FUNC_EXPORT_EAP_ARRAY_ALGORITHMS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_array.h"

/** @file */

//--------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4275 ) // ingnores non dll-interface class 'abs_eap_array_compare_c<class eap_fast_pac_store_data_c>' used as base for dll-interface class 'eap_fast_pac_store_data_compare_A_ID_reference_c'
#endif

template <class Type>
class EAP_CLASS_VISIBILITY_EAP_ARRAY_ALGORITHMS_H abs_eap_array_compare_c
{

public:

	virtual ~abs_eap_array_compare_c()
	{
	}

	virtual i32_t compare(const Type * const original_object_from_array, const Type * const searched_data) const = 0;
};


//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

/**
 * This template function copies class objects from original_array to copy_array. 
 * Type must have the following member functions:
 * Type * copy();
 * bool get_is_valid();
 * bool get_is_valid_data();
 */
template <class Type>
eap_status_e copy(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	eap_array_c<Type> * const copy_array,
	abs_eap_am_tools_c * const m_am_tools,
	const bool when_true_add_objects)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok; // Note original_array may be empty, then for loop will not be run. 

	if (when_true_add_objects == false)
	{
		copy_array->reset();
	}

	for (u32_t ind = 0; ind < original_array->get_object_count(); ind++)
	{
		Type * const orig_object = original_array->get_object(ind);
		if (orig_object == 0
			|| orig_object->get_is_valid() == false)
		{
			EAP_UNREFERENCED_PARAMETER(m_am_tools);
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("copy: orig_object=0x%08x, orig_object->get_is_valid()=%d"),
				 orig_object,
				 (orig_object != 0) ? orig_object->get_is_valid(): false));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		Type * const copy_object = orig_object->copy();
		if (copy_object == 0
			|| copy_object->get_is_valid() == false)
		{
			delete copy_object;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Note the original object might be empty without data.
		if (orig_object->get_is_valid_data() == true
			&& copy_object->get_is_valid_data() == false)
		{
			delete copy_object;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = copy_array->add_object(copy_object, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


//--------------------------------------------------


/**
 * This template function copies simple objects from original_array to copy_array. 
 * Simple types are u16_t, eap_status_e, ...
 */
template <class Type>
eap_status_e copy_simple(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	eap_array_c<Type> * const copy_array,
	abs_eap_am_tools_c * const m_am_tools,
	const bool when_true_add_objects)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok; // Note original_array may be empty, then for loop will not be run. 

	if (when_true_add_objects == false)
	{
		copy_array->reset();
	}

	for (u32_t ind = 0; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{
			EAP_UNREFERENCED_PARAMETER(m_am_tools);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		Type * copy_object = new Type;
		if (copy_object == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		*copy_object = *original_object;

		status = copy_array->add_object(copy_object, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This template function copies data of objects to a eap_variable_data_c object. 
 */
template <class Type>
eap_status_e add_data(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const source_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	eap_variable_data_c * const buffer,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok; // Note source_array may be empty, then for loop will not be run. 

	for (u32_t ind = 0; ind < source_array->get_object_count(); ind++)
	{
		Type * original_object = source_array->get_object(ind);
		if (original_object == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = buffer->add_data(
			original_object->get_data(original_object->get_data_length()),
			original_object->get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("data"),
			original_object->get_data(original_object->get_data_length()),
			original_object->get_data_length()));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This template function copies simple data of objects to a eap_variable_data_c object. 
 */
template <class Type>
eap_status_e add_simple_data(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const source_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	eap_variable_data_c * const buffer,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok; // Note source_array may be empty, then for loop will not be run. 

	for (u32_t ind = 0; ind < source_array->get_object_count(); ind++)
	{
		Type * original_object = source_array->get_object(ind);
		if (original_object == 0)
		{
			EAP_UNREFERENCED_PARAMETER(m_am_tools);
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = buffer->add_data(
			original_object,
			sizeof(*original_object));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("data"),
			original_object,
			sizeof(*original_object)));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This template function searches the supplied array for given object.
 * Function returns the index to the found object or -1 if not found or there 
 * is some other error.
 * Type must have the following member functions:
 * i32_t compare(const Type * const data)
 */
template <class Type>
const i32_t find(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	const Type * const searched_data,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	i32_t index = -1;
	for (u32_t ind = 0; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{			
			index = -1;
			break;
		}
		if (!original_object->compare(const_cast<Type *> (searched_data)))
		{
			// Found it
			index = ind;
			break;
		}
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return index;
}

//--------------------------------------------------

/**
 * This template function searches the supplied array for given object starting from the last index.
 * Function returns the index to the found object or -1 if not found or there 
 * is some other error.
 * Type must have the following member functions:
 * i32_t compare(const Type * const data)
 */
template <class Type>
const i32_t find_next(
	const i32_t last_index,
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	const Type * const searched_data,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	i32_t index = -1;
	for (u32_t ind = last_index+1; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{			
			index = -1;
			break;
		}
		if (!original_object->compare(const_cast<Type *> (searched_data)))
		{
			// Found it
			index = ind;
			break;
		}
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return index;
}

//--------------------------------------------------

/**
 * This template function searches the supplied array for given object.
 * Function returns the index to the found object or -1 if not found or there 
 * is some other error.
 * Type must have the following member functions:
 * i32_t compare(const Type * const data)
 */
template <class Type>
const i32_t find_with_compare(
	const abs_eap_array_compare_c<Type> * const compare,
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	const Type * const searched_data,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	i32_t index = -1;
	for (u32_t ind = 0; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{			
			index = -1;
			break;
		}

		if (!compare->compare(original_object, searched_data))
		{
			// Found it
			index = ind;
			break;
		}
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return index;
}

//--------------------------------------------------

/**
 * This template function searches the supplied array for given object starting from the last index.
 * Function returns the index to the found object or -1 if not found or there 
 * is some other error.
 * Type must have the following member functions:
 * i32_t compare(const Type * const data)
 */
template <class Type>
const i32_t find_next_with_compare(
	const i32_t last_index,
	const abs_eap_array_compare_c<Type> * const compare,
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	const Type * const searched_data,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	i32_t index = -1;
	for (u32_t ind = last_index+1; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{			
			index = -1;
			break;
		}

		if (!compare->compare(original_object, searched_data))
		{
			// Found it
			index = ind;
			break;
		}
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return index;
}

//--------------------------------------------------

/**
 * This template function searches the supplied array for given simple type object.
 * Simple types are u16_t, eap_status_e, ...
 * It returns the index to the found object or -1 if not found or there 
 * is some other error.
 */
template <class Type>
const i32_t find_simple(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	const Type * const searched_data,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	i32_t index = -1;
	for (u32_t ind = 0; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{			
			index = -1;
			break;
		}
		if (*original_object == *searched_data)
		{
			// Found it
			index = ind;
			break;
		}
		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return index;
}

//--------------------------------------------------

/**
 * This template function searches the supplied array for given simple type object.
 * Simple types are u16_t, eap_status_e, ...
 * It returns the index to the found object or -1 if not found or there 
 * is some other error.
 */
template <class Type>
const i32_t find_next_simple(
	const i32_t last_index,
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	const Type * const searched_data,
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	EAP_UNREFERENCED_PARAMETER(m_am_tools);

	i32_t index = -1;
	for (u32_t ind = last_index+1; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);
		if (original_object == 0)
		{			
			index = -1;
			break;
		}
		if (*original_object == *searched_data)
		{
			// Found it
			index = ind;
			break;
		}
		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return index;
}

//--------------------------------------------------

/**
 * Template function for_each() runs supplied function to all type objects of the supplied array.
 */
template <class Type>
eap_status_e for_each(
	EAP_TEMPLATE_CONST eap_array_c<Type> * const original_array, ///< Stupid Windows compiler cannot compile "const eap_array_c<Type> * const".
	eap_status_e (*function)(
		Type * const value,
		abs_eap_am_tools_c * const m_am_tools),
	abs_eap_am_tools_c * const m_am_tools,
	const bool do_not_care_errors)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok; // Note original_array may be empty, then for loop will not be run. 

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("for_each(): function=0x%08x.\n"),
		 function));


	for (u32_t ind = 0; ind < original_array->get_object_count(); ind++)
	{
		Type * original_object = original_array->get_object(ind);

		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("for_each(): object=0x%08x, ")
			 EAPL("function=0x%08x.\n"),
			 original_object,
			 function));

		if (do_not_care_errors == false
			&& original_object == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		else if (original_object != 0)
		{
			status = function(original_object, m_am_tools);

			if (do_not_care_errors == false
				&& status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#endif //#if !defined(_EAP_ARRAY_ALGORITHMS_H_)


//--------------------------------------------------



// End.
