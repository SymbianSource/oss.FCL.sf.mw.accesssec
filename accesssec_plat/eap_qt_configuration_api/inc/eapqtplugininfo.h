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
 *   Control Panel EAP plugin information
 *
 */

/*
 * %version: 2 %
 */

#ifndef EAPQTPLUGININFO_H
#define EAPQTPLUGININFO_H

#include <QString>
#include <eapqtconfigdefs.h>

class EapQtPluginHandle;
class EapQtPluginInfoPrivate;

class EAP_QT_PLUGIN_INFO_EXPORT EapQtPluginInfo
{
public:
    EapQtPluginInfo(const EapQtPluginInfo & info);
    EapQtPluginInfo(EapQtPluginHandle id, QString locId, int orderNumber );
    ~EapQtPluginInfo();

    EapQtPluginHandle pluginHandle() const;
    QString localizationId() const;
    int orderNumber() const;

    EapQtPluginInfo &operator=(const EapQtPluginInfo &info);
    
private:
    EapQtPluginInfo();

    QScopedPointer<EapQtPluginInfoPrivate> d_ptr;
};

#endif
