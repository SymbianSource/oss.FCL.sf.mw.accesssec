/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
 * Description: 
 *   EAP method configuration QT interface
 *
 */

/*
 * %version: 1 %
 */

#ifndef EAPQTCONFIGINTERFACE_H
#define EAPQTCONFIGINTERFACE_H

#include <qglobal.h>

#ifdef BUILD_EAP_QT_CONFIG_INTERFACE_DLL
#define EAP_QT_CONFIG_INTERFACE_EXPORT Q_DECL_EXPORT
#else
#define EAP_QT_CONFIG_INTERFACE_EXPORT Q_DECL_IMPORT
#endif

class EapQtPluginInfo;
class EapQtPluginHandle;
class CpBaseSettingView;

class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtConfigInterface
{
public:
    enum EapBearerType
    {
        EapBearerTypeWlan, EapBearerTypeVpn,
    };
public:
    EapQtConfigInterface(const EapBearerType bearerType, const int databaseIndex);
    ~EapQtConfigInterface();

    QList<EapQtPluginInfo> supportedOuterTypes() const;

    CpBaseSettingView *uiInstance(const EapQtPluginHandle& pluginInfo) const;

private:
};

#endif

