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
 *   Control Panel plugin interface for EAP
 *   method configuration QT UIs
 *
 */

/*
 * %version: 4 %
 */

#ifndef CPEAPPLUGININTERFACE_H
#define CPEAPPLUGININTERFACE_H

// System includes
#include <QtPlugin>
#include <QString>
#include <eapqtconfiginterface.h>

// User includes

// Forward declarations
class CpBaseSettingView;
class EapQtPluginInfo;
class EapQtPluginHandle;

// External data types

// Constants

// All plugin stubs MUST be located in /resource/qt/plugins/controlpanel/eapsecurity
static const QString CpEapPluginInterfacePluginDirectory(
    "\\resource\\qt\\plugins\\controlpanel\\eapsecurity");

// Class declaration
class CpEapPluginInterface
{

public:

    // Data types

    virtual ~CpEapPluginInterface() {};

    virtual void setSettingsReference(const EapQtConfigInterface::EapBearerType bearer,
        const int iapId) = 0;

    virtual QList<EapQtPluginInfo> pluginInfo() = 0;

    virtual CpBaseSettingView* uiInstance(const EapQtPluginHandle &outerHandle,
        const EapQtPluginInfo &plugin) = 0;

};

Q_DECLARE_INTERFACE(CpEapPluginInterface,
    "com.nokia.plugin.controlpanel.eap.platform.interface/1.0");

#endif // CPEAPPLUGININTERFACE_H
