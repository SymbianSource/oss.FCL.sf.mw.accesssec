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




#if !defined( _EAP_EXPORT_H_ )
#define _EAP_EXPORT_H_

#if defined(EAP_NO_EXPORTS)
	// No exports are needed.
	#define EAP_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_IMPORT 
	#define EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_IMPORT_EMPTY 
	#define EAP_FUNC_EXPORT_EMPTY 
	#define EAP_EXPORT 
	#define EAP_NONSHARABLE_CLASS
	#if defined(__WINS__)
		#pragma warning( disable : 4355 )
	#endif /* defined(__WINS__) */
#elif defined(__SYMBIAN32__)
	// This is Symbian compilation.
	#define EAP_FUNC_IMPORT IMPORT_C
	#define EAP_FUNC_EXPORT EXPORT_C
	#define EAP_C_FUNC_IMPORT IMPORT_C
	#define EAP_C_FUNC_EXPORT EXPORT_C
	#define EAP_FUNC_IMPORT_EMPTY 
	#define EAP_FUNC_EXPORT_EMPTY 
	#define EAP_EXPORT 
	#if defined(__WINS__)
		#define EAP_NONSHARABLE_CLASS
	#else
		#define EAP_NONSHARABLE_CLASS __declspec(notshared)
	#endif
	#if defined(__WINS__)
		#pragma warning( disable : 4355 )
	#endif /* defined(__WINS__) */
#elif defined(linux)
	// This is linux compilation.
	#define EAP_FUNC_IMPORT
	#define EAP_FUNC_EXPORT
	#define EAP_C_FUNC_IMPORT
	#define EAP_C_FUNC_EXPORT
	#define EAP_FUNC_IMPORT_EMPTY 
	#define EAP_FUNC_EXPORT_EMPTY 
	#define EAP_EXPORT
	#define EAP_NONSHARABLE_CLASS
#elif defined(__GNUC__)
	// This is cygwin compilation.
	#define EAP_FUNC_IMPORT __declspec(dllexport)
	#define EAP_FUNC_EXPORT
	#define EAP_C_FUNC_IMPORT __declspec(dllexport)
	#define EAP_C_FUNC_EXPORT
	#define EAP_FUNC_IMPORT_EMPTY 
	#define EAP_FUNC_EXPORT_EMPTY 
	#define EAP_EXPORT __declspec(dllexport)
	#define EAP_NONSHARABLE_CLASS
#elif defined(_WIN32) && !defined(__GNUC__)
	// This is windows compilation.
	#define EAP_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT
	#define EAP_C_FUNC_IMPORT __declspec(dllexport)
	#define EAP_C_FUNC_EXPORT
	#define EAP_FUNC_IMPORT_EMPTY 
	#define EAP_FUNC_EXPORT_EMPTY 
	#define EAP_EXPORT __declspec(dllexport)
	#define EAP_NONSHARABLE_CLASS
	#if defined(__WINS__)
		#pragma warning( disable : 4355 )
	#endif /* defined(__WINS__) */
#endif

// This is for separate exports of interface functions.
#if defined(USE_EAP_INTERFACE_EXPORTS)
	#if defined(__SYMBIAN32__)
		#define EAP_FUNC_IMPORT_INTERFACE IMPORT_C
		#define EAP_FUNC_EXPORT_INTERFACE EXPORT_C
		#define EAP_EXPORT_INTERFACE 
	#elif defined(linux)
		#define EAP_FUNC_IMPORT_INTERFACE
		#define EAP_FUNC_EXPORT_INTERFACE
		#define EAP_EXPORT_INTERFACE 
	#elif defined(__GNUC__)
		#define EAP_FUNC_IMPORT_INTERFACE __declspec(dllexport)
		#define EAP_FUNC_EXPORT_INTERFACE
		#define EAP_EXPORT_INTERFACE __declspec(dllexport)
	#elif defined(_WIN32) && !defined(__GNUC__)
		#define EAP_FUNC_IMPORT_INTERFACE 
		#define EAP_FUNC_EXPORT_INTERFACE
		#define EAP_EXPORT_INTERFACE __declspec(dllexport)
	#endif
#else
	#define EAP_FUNC_IMPORT_INTERFACE EAP_FUNC_IMPORT
	#define EAP_FUNC_EXPORT_INTERFACE EAP_FUNC_EXPORT
	#define EAP_EXPORT_INTERFACE EAP_EXPORT
#endif //#if defined(USE_EAP_INTERFACE_EXPORTS)

#endif //#if !defined( _EAP_EXPORT_H_ )



// End.
