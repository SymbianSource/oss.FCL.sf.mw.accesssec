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




#if !defined(_EAP_AUTOMATIC_VARIABLE_H_)
#define _EAP_AUTOMATIC_VARIABLE_H_


#include "eap_am_memory.h"
#include "eap_tools.h"
#include "eap_am_tools.h"
#include "eap_am_export.h"

/**
 * @{ Add some comments. }
 */
template <class Type>
class EAP_EXPORT eap_automatic_variable_c
{
private:
	abs_eap_am_tools_c * const m_am_tools;

	/// This is the pointer to the actual object that will be deleted if different than zero.
	Type *m_data;

public:
	
	/**
	 * The destructor deletes the object in this atom if necessary.	 
	 */	
	virtual ~eap_automatic_variable_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		if (m_data != 0)
		{
			delete m_data;
			m_data = 0;
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
	
	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_automatic_variable_c(
		abs_eap_am_tools_c * const tools,
		Type * const p_data)
		: m_am_tools(tools)
		, m_data(p_data)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_automatic_variable_c(
		abs_eap_am_tools_c * const tools)
		: m_am_tools(tools)
		, m_data(0)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	/**
	 * This function sets the data.
	 */	
	void set_variable(Type * const p_data)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		m_data = p_data;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	//
	void do_not_free_variable()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		m_data = 0;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
};

//--------------------------------------------------

/**
 * @{ Add some comments. }
 */
template <class Type>
class EAP_EXPORT eap_automatic_array_variable_c
{
private:
	abs_eap_am_tools_c * const m_am_tools;

	/// This is the pointer to the actual object array that will be deleted if different than zero.
	Type *m_data;

public:
	
	/**
	 * The destructor deletes the object in this atom if necessary.	 
	 */	
	virtual ~eap_automatic_array_variable_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		if (m_data != 0)
		{
			delete [] m_data;
			m_data = 0;
		}
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
	
	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_automatic_array_variable_c(
		abs_eap_am_tools_c * const tools,
		Type * const p_data)
		: m_am_tools(tools)
		, m_data(p_data)	
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	/**
	 * The constructor sets the values for the member variables
	 */	
	void set_variable(Type * const p_data)
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		m_data = p_data;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	//
	void do_not_free_variable()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		m_data = 0;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
};

//--------------------------------------------------

/**
 * @{ Add some comments. }
 */
template <class Type>
class EAP_EXPORT eap_automatic_simple_value_c
{
private:
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to the variable that will be restored on destructor.
	Type *m_restored_variable;

	/// This is the value that will be set on destructor.
	Type m_data;

public:
	
	/**
	 * The destructor deletes the object in this atom if necessary.	 
	 */	
	virtual ~eap_automatic_simple_value_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		if (m_restored_variable != 0)
		{
			*m_restored_variable = m_data;
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
	
	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_automatic_simple_value_c(
		abs_eap_am_tools_c * const tools,
		Type * const p_restored_variable,
		const Type p_data)
		: m_am_tools(tools)
		, m_restored_variable(p_restored_variable)	
		, m_data(p_data)	
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}

	//
	void do_not_restore_variable()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		m_restored_variable = 0;

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
};


//--------------------------------------------------

/**
 * @{ Add some comments. }
 */
class EAP_EXPORT eap_automatic_trace_string_c
{
private:
	abs_eap_am_tools_c * const m_am_tools;

	/// This is pointer to the string that will be traced on destructor.
	eap_format_string m_string;

public:
	
	/**
	 * The destructor traces the string.
	 */	
	virtual ~eap_automatic_trace_string_c()
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

		if (m_string != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("<<< %s <<<\n"), m_string));
		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
	
	/**
	 * The constructor sets the values for the member variables
	 */	
	eap_automatic_trace_string_c(
		abs_eap_am_tools_c * const tools,
		eap_format_string string)
		: m_am_tools(tools)
		, m_string(string)	
	{
		EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	}
};


#endif //#if !defined(_EAP_AUTOMATIC_VARIABLE_H_)


//--------------------------------------------------



// End.
