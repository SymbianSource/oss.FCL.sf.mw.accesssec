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
 * %version: 21 %
 */

#include <QList>

#include <eapqtconfiginterface.h>
#include <eapqtexpandedeaptype.h>

#include "eapqtconfiginterface_p.h"
#include "cpeapplugininterface.h"

//----------------------------------------------------------------------------
//              EapQtConfigInterface
//----------------------------------------------------------------------------


EapQtConfigInterface::EapQtConfigInterface() :
    d_ptr(new EapQtConfigInterfacePrivate)
{
}

EapQtConfigInterface::EapQtConfigInterface(const EapBearerType bearerType, const int iapId) :
    d_ptr(new EapQtConfigInterfacePrivate(bearerType, iapId))
{
}

EapQtConfigInterface::~EapQtConfigInterface()
{
    // d_ptr is scoped pointer, deleted automatically
}

bool EapQtConfigInterface::setConfigurationReference(const int iapId) const
{
    return d_ptr->setConfigurationReference(iapId);
}

QList<EapQtPluginInfo> EapQtConfigInterface::supportedOuterTypes() const
{
    return d_ptr->supportedOuterTypes();
}

QList<EapQtPluginInfo> EapQtConfigInterface::supportedInnerTypes(const EapQtPluginHandle outerType) const
{
    return d_ptr->supportedInnerTypes(outerType);
}

QList<EapQtCertificateInfo> EapQtConfigInterface::certificateAuthorityCertificates() const
{
    return d_ptr->certificateAuthorityCertificates();
}

QList<EapQtCertificateInfo> EapQtConfigInterface::userCertificates() const
{
    return d_ptr->userCertificates();
}

CpBaseSettingView *EapQtConfigInterface::uiInstance(const EapQtPluginHandle& outerHandle,
    const EapQtPluginHandle &pluginHandle) const
{
    return d_ptr->uiInstance(outerHandle, pluginHandle);
}

QList<EapQtPluginHandle> EapQtConfigInterface::selectedOuterTypes() const
{
    return d_ptr->selectedOuterTypes();
}

bool EapQtConfigInterface::isSupportedOuterType(const EapQtPluginHandle& handle) const
{
    return d_ptr->isSupportedOuterType(handle);
}

bool EapQtConfigInterface::isSupportedInnerType(const EapQtPluginHandle& outerHandle,
    const EapQtPluginHandle& innerHandle) const
{
    return d_ptr->isSupportedInnerType(outerHandle, innerHandle);
}

bool EapQtConfigInterface::setSelectedOuterTypes(const QList<EapQtPluginHandle>& outerHandles) const
{
    return d_ptr->setSelectedOuterTypes(outerHandles);
}

bool EapQtConfigInterface::readConfiguration(const EapQtPluginHandle& outerHandle,
    const EapQtPluginHandle& pluginHandle, EapQtConfig &config) const
{
    return d_ptr->readConfiguration(outerHandle, pluginHandle, config);
}

bool EapQtConfigInterface::saveConfiguration(const EapQtPluginHandle& pluginInfo,
    EapQtConfig &config) const
{
    return d_ptr->saveConfiguration(pluginInfo, config);
}

bool EapQtConfigInterface::deleteConfiguration() const
{
    return d_ptr->deleteConfiguration();
}

EapQtValidator *EapQtConfigInterface::validatorEap(EapQtExpandedEapType type,
    EapQtConfig::SettingsId id)
{
    return d_ptr->validatorEap(type, id);
}
