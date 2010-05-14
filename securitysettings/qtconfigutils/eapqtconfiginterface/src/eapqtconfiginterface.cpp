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

#include <QList>

#include "eapqtconfiginterface.h"
#include "cpeapplugininterface.h"
#include "eapqtplugininfo.h"

//----------------------------------------------------------------------------
//              EapQtConfigInterface
//----------------------------------------------------------------------------

// stub implementation for now

EapQtConfigInterface::EapQtConfigInterface(const EapBearerType /* bearerType */, const int /* databaseIndex */)
{
}

EapQtConfigInterface::~EapQtConfigInterface()
{
}

QList<EapQtPluginInfo> EapQtConfigInterface::supportedOuterTypes() const
{
    // stub
    QList<EapQtPluginInfo> tmp;
    return tmp;
}

CpBaseSettingView *EapQtConfigInterface::uiInstance(const EapQtPluginHandle& /* pluginInfo */) const
{
    // stub
    return NULL;
}
