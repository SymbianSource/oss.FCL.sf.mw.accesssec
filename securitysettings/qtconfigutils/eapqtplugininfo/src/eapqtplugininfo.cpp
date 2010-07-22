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
 *   EAP plugin information
 *
 */

/*
 * %version: 6 %
 */

// System includes
#include <QList>
#include <QVariant>
#include <eapqtpluginhandle.h>
#include <eapqtplugininfo.h>

// User includes
#include "eapqtplugininfo_p.h"

/*!
 *  \class EapQtPluginInfo
 *  \brief Public implementation of EAP plugin information
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtPluginInfo::EapQtPluginInfo(const EapQtPluginHandle &id, const QString &locId,
    const int orderNumber) :
    d_ptr(new EapQtPluginInfoPrivate(id, locId, orderNumber))
{
}

EapQtPluginInfo::EapQtPluginInfo(const EapQtPluginInfo &info) :
    d_ptr(
        new EapQtPluginInfoPrivate(info.pluginHandle(), info.localizationId(), info.orderNumber()))
{
}

EapQtPluginInfo& EapQtPluginInfo::operator=(const EapQtPluginInfo &info)
{
    // check if assigning to myself
    if (this != &info) {
        d_ptr.reset(new EapQtPluginInfoPrivate(info.pluginHandle(), info.localizationId(),
            info.orderNumber()));
    }
    return *this;
}

EapQtPluginInfo::~EapQtPluginInfo()
{
    // scoped pointer delete
}

EapQtPluginHandle EapQtPluginInfo::pluginHandle() const
{
    return d_ptr->mHandle;
}

QString EapQtPluginInfo::localizationId() const
{
    return d_ptr->mLocId;
}

int EapQtPluginInfo::orderNumber() const
{
    return d_ptr->mOrderNumber;
}
