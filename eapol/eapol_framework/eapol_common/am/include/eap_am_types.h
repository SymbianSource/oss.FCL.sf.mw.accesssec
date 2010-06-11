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

/** @file */

#if !defined(_EAP_AM_TYPES_H_)
#define _EAP_AM_TYPES_H_

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if !defined(EAP_NO_STDINT_H_HEADER)
#if defined(__GNUC__)
	#include <stdint.h>
#endif //#if defined(__GNUC__)
#endif //#if !defined(EAP_NO_STDINT_H_HEADER)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(__SYMBIAN32__)
	/// This is unsigned 64-bit integer.
	/// Actual implementation may be signed 64-bit integer.
	/// This depends on Symbian version.
	typedef unsigned long long u64_t;	
#elif defined(__WINSCW__)
	/// This is unsigned 64-bit integer.
	typedef unsigned long long u64_t;	
#elif defined(__GNUC__)
	/// This is unsigned 64-bit integer.
#if defined(EAP_NO_STDINT_H_HEADER)
	typedef unsigned long long u64_t;
#else
	typedef uint64_t u64_t;
#endif //#if defined(EAP_NO_STDINT_H_HEADER)
#else
	/// This is unsigned 64-bit integer. Actually there is not unsigned version.
	typedef __int64 u64_t;
#endif

/// This is unsigned 32-bit integer.
typedef unsigned long int u32_t;
/// This is unsigned 16-bit integer.
typedef unsigned short int u16_t;
/// This is unsigned 8-bit integer.
typedef unsigned char u8_t;

#if defined(__WINSCW__)
	/// This is signed 64-bit integer.
	typedef long long i64_t;
#elif defined(__GNUC__)
	/// This is signed 64-bit integer.
#if defined(EAP_NO_STDINT_H_HEADER)
	typedef long long i64_t;
#else
	typedef int64_t i64_t;
#endif //#if defined(EAP_NO_STDINT_H_HEADER)
#else
	/// This is signed 64-bit integer.
	typedef __int64 i64_t;	
#endif

/// This is signed 32-bit integer.
typedef long int i32_t;

#if defined(__WINSCW__)
	/// This is signed 16-bit integer.
	typedef short i16_t;
#else
	/// This is signed 16-bit integer.
	typedef short int i16_t;
#endif

	/// This is signed 32-bit integer.
typedef char i8_t;


typedef struct
	{
#if defined(EAP_BIG_ENDIAN)
		u32_t high;
		u32_t low;
#elif defined(EAP_LITTLE_ENDIAN)
		u32_t low;
		u32_t high;
#endif
	} u64_struct;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(__SYMBIAN32__)

	/**
	 * This defines const reserved word for template types.
	 * This is because the stupid Windows compiler cannot compile "const template_type<Type> * const".
	 */
	#define EAP_TEMPLATE_CONST const

#elif defined(__GNUC__) || defined(__arm)

	 /**
	 * This defines const reserved word for template types.
	 * This is because the stupid Windows compiler cannot compile "const template_type<Type> * const".
	 */
	#define EAP_TEMPLATE_CONST const

#elif defined(_WIN32)

	 /**
	 * This defines const reserved word for template types.
	 * This is because the stupid Windows compiler cannot compile "const template_type<Type> * const".
	 */
	#define EAP_TEMPLATE_CONST const

#endif

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(__SYMBIAN32__)

	/**
	 * This attribute defines parameter unused. This is not supported in Symbian.
	 */
	#define EAP_ATTRIBUTE_UNUSED

#elif defined(__GNUC__)

	/**
	 * This attribute defines parameter unused. This is not supported in Symbian.
	 */
	#define EAP_ATTRIBUTE_UNUSED __attribute__((unused))

#elif defined(_WIN32)

	/**
	 * This attribute defines parameter unused. This is not supported in windows.
	 */
	#define EAP_ATTRIBUTE_UNUSED

#else

	/**
	 * This attribute defines parameter unused. This is not supported in windows.
	 */
	#define EAP_ATTRIBUTE_UNUSED

#endif

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if defined(__SYMBIAN32__)
	#include <e32std.h>

	/// This is character type.
	typedef i8_t eap_char;
	/// This is constant string type.
	typedef const eap_char * eap_const_string;
	/// This is format string type.
	typedef eap_const_string eap_format_string;
	/// Literal string definition. This is not used currently.
	#define EAPLIT(symbol,param) param
	/// Literal string definition.
	#define EAPL(param) param

	/// This defines literal for database use.
	#define EAP_AM_CONFIGURATION_FIELD_LITERAL(name, field) \
		_LIT( name##_literal, field )

#elif defined(_WIN32) || defined(__GNUC__) || defined(__arm)
	/// This is character type.
	typedef i8_t eap_char;
	/// This is constant string type.
	typedef const eap_char * eap_const_string;
	/// This is format string type.
	typedef eap_const_string eap_format_string;
	/// Literal string definition. This is not used currently.
	#define EAPLIT(symbol,param) param
	/// Literal string definition.
	#define EAPL(param) param

	/// This is not needed here.
	#define EAP_AM_CONFIGURATION_FIELD_LITERAL(name, field)
#else
	#error platform not supported, do something.
#endif

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/// This is configure string type.
typedef const i8_t * eap_config_string;

#if !defined(__SYMBIAN32__)
	#if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)
		#include <stdio.h>
		typedef FILE EAP_FILE_POINTER;
	#endif // #if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)
#endif // !defined(__SYMBIAN32__)

#if defined(USE_EAP_INLINE_FUNCTIONS)
	#define EAP_INLINE inline
#else
	#define EAP_INLINE 
#endif //#if defined(USE_EAP_INLINE_FUNCTIONS)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#endif //#if !defined(_EAP_AM_TYPES_H_)



// End.
