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
* %version: 1 %
*/


#ifndef CPEAPPLUGININTERFACE_H
#define CPEAPPLUGININTERFACE_H

#include <QtPlugin>
#include "eapqtplugininfo.h"

class CpBaseSettingView;
class EapQtConfigInterface;


class CpEapPluginInterface
{
public:
    virtual ~CpEapPluginInterface()
    {
    }
    ;

    virtual void setEapQtConfigInterface(EapQtConfigInterface* configIf) = 0;

    virtual QList<EapQtPluginInfo> pluginInfo() = 0;

    virtual CpBaseSettingView* uiInstance(
        const EapQtPluginInfo &plugin) = 0;
};

Q_DECLARE_INTERFACE(CpEapPluginInterface,
    "com.nokia.plugin.controlpanel.eap.platform.interface/1.0");


#endif
