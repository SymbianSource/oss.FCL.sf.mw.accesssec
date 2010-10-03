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
* %version: 12 %
*/

#if !defined(_EAP_TYPE_MAP_H_)
#define _EAP_TYPE_MAP_H_

#include "eap_am_memory.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_CORE_MAP_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_MAP_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_MAP_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_MAP_H 
	#define EAP_FUNC_EXPORT_EAP_CORE_MAP_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_MAP_H 
#elif defined(EAP_EXPORT_EAP_CORE_MAP_H)
	#define EAP_CLASS_VISIBILITY_EAP_CORE_MAP_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_MAP_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_MAP_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_MAP_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_MAP_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_CORE_MAP_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_CORE_MAP_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_CORE_MAP_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_CORE_MAP_H 
	#define EAP_C_FUNC_EXPORT_EAP_CORE_MAP_H 
#endif
// End: added by script change_export_macros.sh.
#include "abs_eap_core_map.h"
#include "eap_variable_data.h"
#include "eap_am_tools.h"


const u32_t EAP_MAP_SIZE = 256;


#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning (disable : 4251)
#endif


//
template <class Type, class Selector_Type>
class EAP_CLASS_VISIBILITY_EAP_CORE_MAP_H eap_state_map_atom_c
{
private:

	abs_eap_am_tools_c * const m_am_tools;

	Type *m_object;
	Selector_Type *m_selector;
	eap_state_map_atom_c<Type, Selector_Type> *m_next_atom;

	bool m_is_valid;

public:

	//
	virtual ~eap_state_map_atom_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: ~eap_state_map_atom_c(): this 0x%08x starts.\n"),
			 this));

		if (m_selector != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: ~eap_state_map_atom_c(): delete m_selector starts: selector 0x%08x.\n"),
				 m_selector));

			delete m_selector;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: ~eap_state_map_atom_c(): delete m_selector ends.\n")));

			m_selector = 0;
		}

		if (m_object != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: ~eap_state_map_atom_c(): delete m_object starts: object 0x%08x.\n"),
				 m_object));

			delete m_object;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: ~eap_state_map_atom_c(): delete m_object ends.\n")));

			m_object = 0;
		}

		if (m_next_atom != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: ~eap_state_map_atom_c(): delete m_next_atom starts: next atom 0x%08x.\n"),
				 m_next_atom));

			delete m_next_atom;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: ~eap_state_map_atom_c(): delete m_next_atom ends.\n")));

			m_next_atom = 0;
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	//
	eap_state_map_atom_c()
		: m_am_tools(0)
		, m_object(0)
		, m_selector(0)
		, m_next_atom(0)
		, m_is_valid(false)
	{
	}

	//
	eap_state_map_atom_c(
		Selector_Type * const p_selector,
		abs_eap_am_tools_c * const tools,
		Type * const p_object)
		: m_am_tools(tools)
		, m_object(p_object)
		, m_selector(p_selector)
		, m_next_atom(0)
		, m_is_valid(false)
	{
		if (m_am_tools == 0
			|| m_am_tools->get_is_valid() == false
			|| m_object == 0
			|| m_selector == 0)
		{
			return;
		}

		set_is_valid();
	}

	//
	Type * const get_object()
	{
		return m_object;
	}

	//
	const Type * const get_const_object() const
	{
		return m_object;
	}

	//
	void set_object(Type * const p_type)
	{
		m_object = p_type;
	}

	const Selector_Type * const get_selector() const
	{
		return m_selector;
	}

	eap_state_map_atom_c * const get_next_atom() const
	{
		return m_next_atom;
	}

	void set_next_atom(eap_state_map_atom_c<Type, Selector_Type> * const next)
	{
		m_next_atom = next;
	}

	void set_is_valid()
	{
		m_is_valid = true;
	}

	bool get_is_valid()
	{
		return m_is_valid;
	}
};


/// This template class stores the Type identified with Selector_Type.
/**
  * A eap_core_map_c template class.
  * The eap_core_map_c template class includes an array that is indexed with 
  * type of Selector_Type parameter.
  * @param Type template parameter is the actual type which is stored.
  * @param Abs_Type template parameter is the abstract partner type of Type.
  * @param Selector_Type template type is the type of the selector object.
  * The Selector_Type could be any class that offers three functions with 
  * the following prototypes:
  * @code
  * i32_t compare(
  * 	const Selector_Type * const data) const;
  * 
  * u32_t hash(
  * 	const u32_t size) const;
  * 
  * Selector_Type * const copy() const;
  * @endcode
  *
  * The Type could be any class that offers two functions with
  * the following prototypes:
  * @code
  * void object_increase_reference_count();
  *
  * u32_t object_decrease_reference_count();
  *
  * @endcode
  *
  */
template <class Type, class Abs_Type, class Selector_Type>
class EAP_CLASS_VISIBILITY_EAP_CORE_MAP_H eap_core_map_c
{
private:
	//--------------------------------------------------

	/// This is back pointer to object which created this object.
	Abs_Type * const m_partner;

	/// This is hash-table to all objects stored to the eap_core_map object.
	/// Objects are stored using the eap_state_map_atom template class.
	eap_state_map_atom_c<Type, Selector_Type> *m_map[EAP_MAP_SIZE];

	/// This is pointer to the tools class. 
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_core_map template class deletes all stored objects.
	 */
	virtual ~eap_core_map_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		(void) reset();

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	/**
	 * The constructor initializes attributes using the passed parameters.
	 * Each pointer of m_map array is initialized null.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 * @param partner is back pointer to object which created this object.
	 */
	eap_core_map_c(
		abs_eap_am_tools_c * const tools,
		Abs_Type * const partner)
	: m_partner(partner)
	, m_am_tools(tools)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		for (u32_t ind = 0u; ind < EAP_MAP_SIZE; ind++)
		{
			m_map[ind] = 0;
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	u32_t get_atom_count() const
	{
		return EAP_MAP_SIZE;
	}

	const eap_state_map_atom_c<Type, Selector_Type> *get_atom(const u32_t index) const
	{
		if (index >= EAP_MAP_SIZE)
		{
			return 0;
		}

		return m_map[index];
	}

	/**
	 * The add_handler() function stores a new type to the eap_core_map object.
	 * @param p_selector is pointer to a selector object.
	 * The p_selector object identifies the stored type.
	 * @param type is pointer to the stored object.
	 */
	eap_status_e add_handler(
		const Selector_Type * const p_selector,
		Type * const object)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		const u32_t index = p_selector->hash(EAP_MAP_SIZE);

		if (index >= EAP_MAP_SIZE)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_hashed_index);
		}

		eap_state_map_atom_c<Type, Selector_Type> *cursor = m_map[index];
		eap_state_map_atom_c<Type, Selector_Type> *last_cursor = 0;

		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: add_handler(): index %d\n"),
			index));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: selector"),
			p_selector->get_data(p_selector->get_data_length()),
			p_selector->get_data_length()));

		while (cursor != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: add_handler(): cursor 0x%08x\n"),
				cursor));

			if (p_selector->compare(cursor->get_selector()) == 0)
			{
				// match
				break;
			}
			last_cursor = cursor;
			cursor = cursor->get_next_atom();
		}

		if (cursor != 0)
		{
			// Already exists.
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CORE_MAP: add_handler(): index %d\n"),
				index));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CORE_MAP: cursor"),
				cursor->get_selector()->get_data(cursor->get_selector()->get_data_length()),
				cursor->get_selector()->get_data_length()));

			return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_exists_error);
		}
		else
		{
			eap_state_map_atom_c<Type, Selector_Type> *atom
				= new eap_state_map_atom_c<Type, Selector_Type>(
					p_selector->copy(), m_am_tools, object);

			if (atom == 0
				|| atom->get_is_valid() == false)
			{
				delete atom;
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: add_handler(): atom 0x%08x, object 0x%08x\n"),
				atom,
				object));

			if (last_cursor != 0)
			{
				last_cursor->set_next_atom(atom);
			}
			else
			{
				m_map[index] = atom;
			}

			object->object_increase_reference_count();
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}


	/**
	 * @return The get_handler() function returns a pointer to the type object or NULL.
	 * @param p_selector is pointer to a selector object.
	 * The p_selector object identifies the required object.
	 */
	Type * const get_handler(
		const Selector_Type * const p_selector) const
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		if (p_selector->get_is_valid() == false)
		{
			return 0;
		}

		Type *object = 0;
		const u32_t index = p_selector->hash(EAP_MAP_SIZE);

		if (index >= EAP_MAP_SIZE)
		{
			return 0;
		}

		eap_state_map_atom_c<Type, Selector_Type> *cursor = m_map[index];

		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: get_handler(): index %d\n"),
			index));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: selector"),
			p_selector->get_data(p_selector->get_data_length()),
			p_selector->get_data_length()));

		while (cursor != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: get_handler(): cursor 0x%08x\n"),
				cursor));

			if (p_selector->compare(cursor->get_selector()) == 0)
			{
				// match
				break;
			}

			cursor = cursor->get_next_atom();
		}

		if (cursor != 0)
		{
			object = cursor->get_object();

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: get_handler(): found cursor 0x%08x\n"),
				cursor));

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: get_handler(): found object 0x%08x\n"),
				object));
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: get_handler(): NOT found\n")));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return object;
	}


	/**
	 * The remove_handler() function removes and deletes the object from MAP.
	 * @param p_selector is pointer to a selector object.
	 * @param delete_object tells whether the object is deleted (true) or not (false).
	 * The p_selector object identifies the removed object.
	 */
	eap_status_e remove_handler(
		const Selector_Type * const p_selector,
		const bool delete_object)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		const u32_t index = p_selector->hash(EAP_MAP_SIZE);

		if (index >= EAP_MAP_SIZE)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_hashed_index);
		}

		eap_state_map_atom_c<Type, Selector_Type> *cursor = m_map[index];
		eap_state_map_atom_c<Type, Selector_Type> *last_cursor = 0;

		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: remove_handler(): index %d\n"),
			index));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: selector"),
			p_selector->get_data(p_selector->get_data_length()),
			p_selector->get_data_length()));

		while (cursor != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_MASK_HASH_MAP,
				(EAPL("CORE_MAP: remove_handler(): cursor 0x%08x\n"),
				cursor));

			if (p_selector->compare(cursor->get_selector()) == 0)
			{
				if (cursor->get_object()->object_decrease_reference_count() > 0u)
				{
					// Other users of the EAP-type are still active.
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, eap_status_state_reference_count_not_zero);
				}
				// match
				break;
			}
			last_cursor = cursor;
			cursor = cursor->get_next_atom();
		}

		if (cursor == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_handler_does_not_exists_error);
		}

		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: remove_handler(): cursor 0x%08x, object 0x%08x\n"),
			cursor,
			cursor->get_object()));

		if (last_cursor != 0)
		{
			last_cursor->set_next_atom(cursor->get_next_atom());
		}
		else
		{
			m_map[index] = cursor->get_next_atom();
		}
		cursor->set_next_atom(0);

		if (delete_object == false)
		{
			// Object will be used on other location.
			// We do not delete it here.
			cursor->set_object(0);
		}

		delete cursor;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}


	/**
	 * The for_each() function runs function for the each object in the MAP.
	 * @param p_selector is pointer to a selector object.
	 * The p_selector object identifies the removed object.
	 */
	eap_status_e for_each(
		eap_status_e (*function)(
			Type * const value,
			abs_eap_am_tools_c * const m_am_tools),
		const bool /* do_not_care_errors */)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		u32_t index = 0ul;

		for (index = 0ul; index < EAP_MAP_SIZE; index++)
		{
			eap_state_map_atom_c<Type, Selector_Type> *cursor = m_map[index];

			while (cursor != 0)
			{
				eap_status_e status = function(cursor->get_object(), m_am_tools);

				if (status != eap_status_ok)
				{
					EAP_TRACE_DEBUG(
						m_am_tools,
						EAP_TRACE_MASK_HASH_MAP,
						(EAPL("CORE_MAP: ERROR: for_each(): cursor 0x%08x, status %d\n"),
						 cursor,
						 status));
				}

				cursor = cursor->get_next_atom();

			} // while()
		} // for()

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	bool get_is_valid()
	{
		return true;
	}

	eap_status_e reset()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_HASH_MAP,
			(EAPL("CORE_MAP: eap_core_map_c::reset(): this 0x%08x starts.\n"),
			 this));

		for (u32_t ind = 0u; ind < EAP_MAP_SIZE; ind++)
		{
			if (m_map[ind] != 0)
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					EAP_TRACE_MASK_HASH_MAP,
					(EAPL("CORE_MAP: eap_core_map_c::reset(): delete m_map[%d], atom 0x%08x starts.\n"),
					ind,
					m_map[ind]));

				eap_state_map_atom_c<Type, Selector_Type> *tmp = m_map[ind];
				m_map[ind] = 0;
				delete tmp;

				EAP_TRACE_DEBUG(
					m_am_tools,
					EAP_TRACE_MASK_HASH_MAP,
					(EAPL("CORE_MAP: eap_core_map_c::reset(): delete m_map[%d] ends.\n"),
					ind));
			}
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	//--------------------------------------------------
}; // class eap_core_map_c

#endif //#if !defined(_EAP_TYPE_MAP_H_)


//--------------------------------------------------



// End.
