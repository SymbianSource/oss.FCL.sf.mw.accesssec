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
 *   Export definition file for EAP QT configuration API
 *   headers
 *
 */

/*
 * %version: 3 %
 */

#ifndef EAPQTCONFIGEXPORT_H_
#define EAPQTCONFIGEXPORT_H_

#ifdef BUILD_EAP_QT_CONFIG_INTERFACE_DLL
// the class gets exported
#define EAP_QT_CONFIG_INTERFACE_EXPORT Q_DECL_EXPORT
#else
// the class gets imported (used)
#define EAP_QT_CONFIG_INTERFACE_EXPORT Q_DECL_IMPORT
#endif

#ifdef BUILD_EAP_QT_PLUGIN_INFO_DLL
// the class gets exported
#define EAP_QT_PLUGIN_INFO_EXPORT Q_DECL_EXPORT
#else
// the class gets imported (used)
#define EAP_QT_PLUGIN_INFO_EXPORT Q_DECL_IMPORT
#endif

#endif // EAPQTCONFIGEXPORT_H_
