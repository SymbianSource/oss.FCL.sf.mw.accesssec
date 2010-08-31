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
 *   Control Panel QT plugin for EAP-SIM and EAP-AKA 
 *   method configuration
 *
 */

/*
 * %version:  7 %
 */

#ifndef CPEAPSIMAKAPLUGIN_H
#define CPEAPSIMAKAPLUGIN_H

// System includes
#include <QObject>
// User includes
#include "cpeapplugininterface.h"

// Forward declarations

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_simaka
 * @{
 */
class CpEapSimAkaPlugin: public QObject, public CpEapPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpEapPluginInterface)

public:
    CpEapSimAkaPlugin();
    ~CpEapSimAkaPlugin();

    void setSettingsReference(const EapQtConfigInterface::EapBearerType bearer, const int iapId);
    QList<EapQtPluginInfo> pluginInfo();
    CpBaseSettingView* uiInstance(const EapQtPluginHandle& outerHandle,
        const EapQtPluginInfo &plugin);

private:
    EapQtConfigInterface::EapBearerType mBearer;
    int mIapId;
};

/*! @} */

#endif
