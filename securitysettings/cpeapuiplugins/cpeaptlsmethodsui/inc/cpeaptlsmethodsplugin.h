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
 *   Control Panel QT plugin for TLS-based EAP methods configuration
 *
 */

/*
 * %version:  7 %
 */

#ifndef CPEAPTLSMETHODSPLUGIN_H
#define CPEAPTLSMETHODSPLUGIN_H

// System includes
#include <QObject>

// User includes
#include "cpeapplugininterface.h"

// Forward declarations

// External data types

// Constants

/*!
 * @addtogroup group_eap_ui_plugin_tlsmethods
 * @{
 */
// Class declaration
class CpEapTlsMethodsPlugin : public QObject, public CpEapPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpEapPluginInterface)

public:
    CpEapTlsMethodsPlugin();
    ~CpEapTlsMethodsPlugin();

    void setSettingsReference(const EapQtConfigInterface::EapBearerType bearer, const int iapId);
    QList<EapQtPluginInfo> pluginInfo();
    CpBaseSettingView* uiInstance(const EapQtPluginHandle& outerHandle,
        const EapQtPluginInfo &plugin);

signals:

public slots:

protected:

protected slots:

private:

private slots:

private:
    //! Bearer type
    EapQtConfigInterface::EapBearerType mBearer;
    //! IAP ID
    int mIapId;
};

/*! @} */

#endif
