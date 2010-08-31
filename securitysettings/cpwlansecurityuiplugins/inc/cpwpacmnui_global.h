/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description:
 *  Export Declaration for CpWpaCmnUi DLL - common Ui
 *  for WPA/WPA2, WPA2 only and 802.1x  Security modes
 *    
 */

/*
 * %version: tr1cfwln#7 %
 */

#ifndef CPWPACMNUI_GLOBAL_H_
#define CPWPACMNUI_GLOBAL_H_


#include <QtCore/QtGlobal>
 
 //If WPAUI_LIBRARY macro is defined in the project file,
 //The dll is exported, 
 //otherwise, 
 //the dll will be imported(used)
 #if defined(WPAUI_LIBRARY)
 #define WPAUI_EXPORT Q_DECL_EXPORT
 #else
 #if defined(WPAUI_NO_LIBRARY)
 #define WPAUI_EXPORT
 #else
 #define WPAUI_EXPORT Q_DECL_IMPORT
 #endif
 #endif


#endif //CPWPACMNUI_GLOBAL_H_
