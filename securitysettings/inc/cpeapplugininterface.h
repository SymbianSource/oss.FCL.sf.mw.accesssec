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
 *   Control Panel plug-in interface for EAP method configuration QT UIs
 *
 */

/*
 * %version: 2 %
 */

#ifndef CPEAPPLUGININTERFACE_H
#define CPEAPPLUGININTERFACE_H

#include <QtPlugin>
#include <eapqtconfiginterface.h>

class CpBaseSettingView;
class EapQtPluginInfo;
class EapQtPluginHandle;

/*!
 * @addtogroup group_eap_ui_plugin
 * @{
 */

/*! Qt Plugin interface for EAP settings in Control Panel application.
 * 
 * All plugin stubs MUST be in 
 * /resource/qt/plugins/controlpanel/eapsettings
 */
class CpEapPluginInterface
{
public:
    /*! Destructor */
    virtual ~CpEapPluginInterface()
    {
    }
    ;

    virtual void setSettingsReference(const EapQtConfigInterface::EapBearerType bearer,
        const int iapId) = 0;

    virtual QList<EapQtPluginInfo> pluginInfo() = 0;

    virtual CpBaseSettingView* uiInstance(const EapQtPluginHandle& outerHandle,
        const EapQtPluginInfo& plugin) = 0;
};

Q_DECLARE_INTERFACE(CpEapPluginInterface,
    "com.nokia.plugin.controlpanel.eap.platform.interface/1.0");

/*! @} */

#endif
