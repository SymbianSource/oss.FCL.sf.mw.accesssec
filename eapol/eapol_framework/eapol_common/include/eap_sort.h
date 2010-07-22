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

#if !defined(_EAP_SORT_H_)
#define _EAP_SORT_H_

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_automatic_variable.h"

/** @file */

//--------------------------------------------------

/**
 * This template function copies array of objects from first to last
 * to array of objects ending to result.
 * Parameter first point to the first object of the source array.
 * Parameter last points the next address after the last object of source array.
 * Parameter result points the next address after the last object of the result array.
 */
template <class Type>
void eap_sort_copy_backward(
	const Type * const first,
	const Type *last,
	Type *result )
{
	while (first != last)
	{
		*--result = *--last;
	}
}

//--------------------------------------------------

/**
 * 
 */
template <class Type>
void eap_sort_unguarded_linear_insert(
	Type *last,
	const Type inserted_object,
	bool (*compare_first_is_smaller)(
		const Type * const first,
		const Type * const second,
		abs_eap_am_tools_c * const m_am_tools),
	abs_eap_am_tools_c * const m_am_tools)
{
	Type *next = last;

	--next;

	while(compare_first_is_smaller(&inserted_object, next, m_am_tools) == true)
	{
		*last = *next;
		last = next--;
	}

	*last = inserted_object;
}

//--------------------------------------------------

template <class Type>
void eap_sort_linear_insert(
	Type * const first,
	Type * const last,
	bool (*compare_first_is_smaller)(
		const Type * const first,
		const Type * const second,
		abs_eap_am_tools_c * const m_am_tools),
	abs_eap_am_tools_c * const m_am_tools)
{
	const Type value = *last;

	if(compare_first_is_smaller(&value, first, m_am_tools) == true)
	{
		eap_sort_copy_backward(first, last, last+1);
		*first = value;
	}
	else
	{
		eap_sort_unguarded_linear_insert(last, value, compare_first_is_smaller, m_am_tools);
	}
}

//--------------------------------------------------

template <class Type>
void eap_sort_insert_sort_area(
	Type * const first,
	const Type *last,
	bool (*compare_first_is_smaller)(
		const Type * const first,
		const Type * const second,
		abs_eap_am_tools_c * const m_am_tools),
	abs_eap_am_tools_c * const m_am_tools)
{
	Type *tmp;

	++last;

	for( tmp = first+1; tmp < last; tmp++ )
	{
		eap_sort_linear_insert( first, tmp, compare_first_is_smaller, m_am_tools);
	}
}

//------------------------------------------------------------


template <class Type>
Type *eap_sort_divide_area(
	Type *start,
	Type *finish,
	bool (*compare_first_is_smaller)(
		const Type * const first,
		const Type * const second,
		abs_eap_am_tools_c * const m_am_tools),
	abs_eap_am_tools_c * const m_am_tools)
{
	// selects the boundary object.
	const Type boundary = *(start+((finish - start)/2));
	Type change;

	start--;
	finish++;

	// Boundary is used as a middle object.
	for(;;)
	{
		// Examine from begin to end is ++start smaller than boundary.
		while(compare_first_is_smaller(++start, &boundary, m_am_tools) == true)
		{
			// Nothing to do.
		}

		// Examine from end to begin is --finish bigger than boundary.
		while(compare_first_is_smaller(&boundary, --finish, m_am_tools) == true)
		{
			// Nothing to do.
		}


		if( start < finish )
		{
			// In case boundary isn't reached, it intent that two
			// atom mutual side of boundary are in wrong order,
			// so swap them.
			change = *start;
			*start = *finish;
			*finish = change;
		}
		else
		{
			// Start and finish pointers are overlapping.
			// Terminate loop and return pointer to finish.
			return( finish );
		}
	} // for()

}

//--------------------------------------------------

/**
 * This function does quick-sort with non-recurvive alorithm.
 * Parameter array is pointer to array including objects of type Type.
 * Parameter object_count is count of objects in the array.
 * Parameter compare_first_is_smaller is pointer to a function that compares objects of type Type.
 */
template <class Type>
eap_status_e eap_sort_array(
	Type * const array,
	const u32_t object_count,
	bool (*compare_first_is_smaller)(
		const Type * const first,
		const Type * const second,
		abs_eap_am_tools_c * const m_am_tools),
	abs_eap_am_tools_c * const m_am_tools)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	eap_status_e status = eap_status_ok; // Note original_array may be empty or it includes only one object, then sort will not be run. 

	if (object_count < 2ul)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	const u32_t quicksort_finish = 10ul;

	// When there are atoms in the array fewer than quicksort_finish,
	// then the array is sorted directly by eap_sort_insert_sort_area() function.
	if (object_count >= quicksort_finish)
	{
		Type ** const sort_array = new Type *[object_count+1];
		eap_automatic_array_variable_c<Type *> automatic_sort_array(m_am_tools, sort_array);
		if (sort_array == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// first atom
		Type *start = array;
		// last point to the first address after the last atom.
		Type *last = array+object_count;
		Type *finish = last - 1;
		sort_array[finish-array] = finish;

		// We continue until start come real array's end.
		while (last != start)
		{
			if (static_cast<u32_t>(finish - start) > quicksort_finish)
			{
				Type *upper = eap_sort_divide_area(start, finish , compare_first_is_smaller, m_am_tools);

				// When is at least two unit in beginning.
				// Divide sorting area under upper address.
				// Upper areas end points are saved to sort_array.
				sort_array[upper+1-array] = finish;

				// New sorting area.
				// New start address is the same as start pointer of previous sort area.
				// New finish address is preceding address of upper address.
				finish = upper;
			}
			else
			{
				eap_sort_insert_sort_area(start, finish , compare_first_is_smaller, m_am_tools);

				start = ++finish;
				finish = sort_array[start-array];
			}
		} // while ( last != start )
	}
	else
	{
		eap_sort_insert_sort_area(array, array+(object_count-1), compare_first_is_smaller, m_am_tools);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#endif //#if !defined(_EAP_SORT_H_)


//--------------------------------------------------



// End.
