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
 *   Control Panel EAP plug-in information
 *
 */

/*
 * %version: 1 %
 */

#include <QList>
#include <QVariant>

#include "eapqtplugininfo.h"

//----------------------------------------------------------------------------
//              EapQtPluginInfo
//----------------------------------------------------------------------------

// stub implementation for now

EapQtPluginInfo::EapQtPluginInfo(EapQtPluginHandle /* id */, QString /* locId */, int /* orderNumber */)
{
}

EapQtPluginInfo::~EapQtPluginInfo()
{
}

EapQtPluginHandle EapQtPluginInfo::pluginHandle() const
{
    EapQtPluginHandle tmp;
    return tmp;
}

QString EapQtPluginInfo::localizationId() const
{
    return QString();
}

int EapQtPluginInfo::orderNumber() const
{
    return 0;
}
