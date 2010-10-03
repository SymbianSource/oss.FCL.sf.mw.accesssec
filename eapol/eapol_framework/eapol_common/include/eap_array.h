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

#if !defined(_EAP_ARRAY_H_)
#define _EAP_ARRAY_H_

#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_ARRAY_H)
	#define EAP_CLASS_VISIBILITY_EAP_ARRAY_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_ARRAY_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_ARRAY_H 
	#define EAP_FUNC_EXPORT_EAP_ARRAY_H 
	#define EAP_C_FUNC_EXPORT_EAP_ARRAY_H 
#elif defined(EAP_EXPORT_EAP_ARRAY_H)
	#define EAP_CLASS_VISIBILITY_EAP_ARRAY_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_ARRAY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_ARRAY_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_ARRAY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_ARRAY_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_ARRAY_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_ARRAY_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_ARRAY_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_ARRAY_H 
	#define EAP_C_FUNC_EXPORT_EAP_ARRAY_H 
#endif
// End: added by script change_export_macros.sh.

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4251 ) // needs to have dll-interface to be used by clients
#endif

#define EAP_ARRAY_SANITY_CHECK(this) \
	{ \
		EAP_ASSERT(((this)->m_head == 0 && (this)->m_tail == 0 && (this)->m_object_count == 0) \
				   || ((this)->m_head != 0 && (this)->m_tail != 0 && (this)->m_object_count != 0)); \
		\
		EAP_ASSERT(((this)->m_object_count == 0 && (this)->m_head == 0) \
				   || ((this)->m_object_count == 1 && (this)->m_head != 0 \
					   && (this)->m_head == (this)->m_tail && (this)->m_head->get_next_atom() == 0) \
				   || ((this)->m_object_count > 1 && (this)->m_head != 0 \
					   && (this)->m_head != (this)->m_tail && (this)->m_head->get_next_atom() != 0)); \
		\
		EAP_ASSERT(((this)->m_object_count == 0 && (this)->m_tail == 0) \
				   || ((this)->m_object_count != 0 && (this)->m_tail != 0 && (this)->m_tail->get_next_atom() == 0)); \
	}

//----------------------------------------------------------------------------------------

/**
 * The eap_array_atom_c is a template class for single object stored to eap_array_c array.
 * The array objects are stored as a linked list.
 * @param Type template parameter is the actual type which is stored.
 */
template <class Type>
class EAP_CLASS_VISIBILITY_EAP_ARRAY_H eap_array_atom_c
{
private:

	/// This is pointer to the tools class. 
	abs_eap_am_tools_c * m_am_tools;

	/// This is the pointer to the actual object
	Type *m_data;

	/// Linked list pointer to the next atom
	eap_array_atom_c<Type> *m_next_atom;

	/// This flag indicates whether eap_array deletes the stored object when it is destroyed.
	bool m_free_atom;

public:
	
	/**
	 * The destructor deletes the object in this atom if necessary.	 
	 */	
	virtual ~eap_array_atom_c()
	{
		m_am_tools = 0;

		if (m_data != 0 
			&& m_free_atom == true)
		{
			delete m_data;
			m_data = 0;
		}
	}
	
	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_array_atom_c(
		abs_eap_am_tools_c * const tools,
		Type * const p_data,
		const bool free_atom)
		: m_am_tools(tools)
		, m_data(p_data)	
		, m_next_atom(0)
		, m_free_atom(free_atom)
	{
	}

	//
	Type * const get_data()
	{
		return m_data;
	}

	//
	void set_data(Type * const p_data)
	{
		m_data = p_data;
	}

	eap_array_atom_c * const get_next_atom() const
	{
		return m_next_atom;
	}
	
	void set_next_atom(eap_array_atom_c<Type> * const next)
	{
		m_next_atom = next;
	}
};

//----------------------------------------------------------------------------------------

/**
  * The eap_array_c template class includes an array for type of Type objects.
  * The objects can be added, retrieved and their count can be queried.
  * @param Type template parameter is the actual type which is stored.
  */
template <class Type>
class EAP_CLASS_VISIBILITY_EAP_ARRAY_H eap_array_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class. 
	abs_eap_am_tools_c * m_am_tools;

	/// Head pointer for the object atom linked list. 
	eap_array_atom_c<Type> *m_head;

	/// Tail pointer for the object atom linked list. 
	eap_array_atom_c<Type> *m_tail;

	/// This is the number of objects
	u32_t m_object_count;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The constructor initializes attributes using the passed parameter.
	 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
	 */
	eap_array_c(
		abs_eap_am_tools_c * const tools)
		: m_am_tools(tools)
		, m_head(0)
		, m_tail(0)
		, m_object_count(0)
	{		
	}

	/**
	 * Destructor deletes all atoms.
	 */		
	virtual ~eap_array_c()
	{
		(void) reset();
		m_am_tools = 0;
	}

	// NOTE: This operator is NOT supported. This is unplemented prototype to cause linker error if assigment operator is used.
	eap_array_c<Type> &operator = (const eap_array_c<Type> &right_type_value);


	/**
	 * reset() deletes all atoms.
	 */		
	eap_status_e reset()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		EAP_ARRAY_SANITY_CHECK(this);

		if (m_head == 0)
		{
			// The array is empty
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return eap_status_ok;
		}

		eap_array_atom_c<Type> *current;
		eap_array_atom_c<Type> *last;

		// Go through the linked list and delete all
		current = m_head;

		while (current != 0)
		{
			last = current;
			current = last->get_next_atom();
			delete last;
		}

		m_object_count = 0UL;
		m_head = 0;
		m_tail = 0;

		EAP_ARRAY_SANITY_CHECK(this);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	/**
	 * The function add_object_to_begin() adds one new object to the begin of the array.
	 * @param object is pointer to the added object
	 * @param m_free_object is flag that indicates whether the object should be deleted by eap_array_c
	 */		
	eap_status_e add_object_to_begin(
		Type * const object,
		const bool m_free_object)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		eap_array_atom_c<Type> *atom;

		if (object == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_ARRAY_SANITY_CHECK(this);

		atom = new eap_array_atom_c<Type>(m_am_tools, object, m_free_object);
		if (atom == 0
			|| object == 0)
		{
			if (m_free_object == true)
			{
				delete object;
			}

			EAP_ARRAY_SANITY_CHECK(this);

			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Check if this is the first item
		if (m_head == 0)
		{
			// Yes
			m_head = atom;
			m_tail = atom;
		}
		else 
		{
			// No. Add it to the begin.
			atom->set_next_atom(m_head);
			m_head = atom;
		}

		m_object_count++;

		EAP_ARRAY_SANITY_CHECK(this);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	/**
	 * The function add_object() adds one new object to the array.
	 * @param object is pointer to the added object
	 * @param m_free_object is flag that indicates whether the object should be deleted by eap_array_c
	 */		
	eap_status_e add_object(
		Type * const object,
		const bool m_free_object)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		eap_array_atom_c<Type> *atom;

		if (object == 0)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		EAP_ARRAY_SANITY_CHECK(this);

		atom = new eap_array_atom_c<Type>(m_am_tools, object, m_free_object);
		if (atom == 0)
		{
			if (m_free_object == true)
			{
				delete object;
			}

			EAP_ARRAY_SANITY_CHECK(this);

			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// Check if this is the first item
		if (m_head == 0)
		{
			// Yes
			m_head = atom;
			m_tail = atom;
		}
		else 
		{
			// No. Add it to the end.
			m_tail->set_next_atom(atom);
			m_tail = atom;
		}

		m_object_count++;

		EAP_ARRAY_SANITY_CHECK(this);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return eap_status_ok;
	}

	/**
	 * The get_object() function returns object based on the index given.
	 * @param index Indicates which object pointer is returned
	 * @return Object pointer
	 */			
	Type * const get_object(const u32_t index) const
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_ASSERT_ALWAYS(index < get_object_count());

		EAP_ARRAY_SANITY_CHECK(this);

		eap_array_atom_c<Type> *atom;
		Type *object = 0;
		atom = m_head;
		u32_t i = 0;

		// find the object needed by stepping through the array.
		while (atom != 0)
		{	
			// Is this the correct one?
			if (index == i)
			{
				// Yes.
				object = atom->get_data();
				break;
			}

			// Nope. Get the next one
			i++;
			atom = atom->get_next_atom();
		}

		EAP_ARRAY_SANITY_CHECK(this);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return object;
	}

	/**
	 * The remove_object() function removes object based on the index given.
	 * @param index Indicates which object pointer is returned
	 * @return Object pointer
	 */			
	eap_status_e remove_object(const u32_t index)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_ASSERT_ALWAYS(index < get_object_count());

		EAP_ARRAY_SANITY_CHECK(this);

		eap_array_atom_c<Type> *atom;
		eap_array_atom_c<Type> *prev_atom = 0;
		atom = m_head;
		u32_t i = 0;
		eap_status_e status = eap_status_illegal_index;

		// find the object needed by stepping through the array.
		while (atom != 0)
		{	
			// Is this the correct one?
			if (index == i)
			{
				// Yes.
				if (index == 0
					&& prev_atom == 0)
				{
					// this is the first on the array.
					m_head = atom->get_next_atom();
					if (m_head == 0)
					{
						m_tail = 0;
					}
				}
				else
				{
					prev_atom->set_next_atom(atom->get_next_atom());
				}

				if (m_tail == atom)
				{
					// This is the last on the array.
					m_tail = prev_atom;
				}

				delete atom;
				--m_object_count;

				EAP_ARRAY_SANITY_CHECK(this);

				status = eap_status_ok;
				break;
			}

			// Nope. Get the next one
			i++;
			prev_atom = atom;
			atom = atom->get_next_atom();

		} // while()

		EAP_ARRAY_SANITY_CHECK(this);

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	/**
	 * The get_object_count() function returns the number of objects in the array.
	 * @return number of objects
	 */			
	const u32_t get_object_count() const
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return m_object_count;
	}

	/**
	 * Gets last object.
	 * @return Object pointer or null if array is empty.
	 */			
	Type * const get_last_object() const
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		EAP_ARRAY_SANITY_CHECK(this);

		// find the object needed by stepping through the array.
		if (get_object_count() > 0UL
			&& m_tail != 0)
		{	
			// Yes.
			Type * const object = m_tail->get_data();
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return object;
		}
		else
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return 0;
		}
	}

	//--------------------------------------------------
}; // class eap_array_c

//----------------------------------------------------------------------------------------

#endif //#if !defined(_EAP_ARRAY_H_)




// End.
